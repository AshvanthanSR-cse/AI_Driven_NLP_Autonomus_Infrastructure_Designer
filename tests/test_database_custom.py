"""Database recipe: new engines and the Customize path (every option, extra AWS parameters, teardown order)."""
import json

from core import recipes, router, scripts, templates
from core.templates import TaskQuestions
from tests.test_recipes import RecipeTest


def ops(d):
    return [f"{s['service']}.{s['operation']}" for s in d.steps]


def step(d, op, n=0):
    return [s for s in d.steps if f"{s['service']}.{s['operation']}" == op][n]


class TestDatabaseCustom(RecipeTest):
    def test_defaults_unchanged_when_not_customized(self):
        d = self.build("database", {"engine": "postgres", "name": "shop-db"})
        p = step(d, "rds.create_db_instance")["params"]
        self.assertFalse(p["MultiAZ"])
        self.assertEqual((p["BackupRetentionPeriod"], p["StorageType"]), (1, "gp3"))
        self.assertNotIn("EngineVersion", p)

    def test_postgres_every_option(self):
        d = self.build("database", {
            "engine": "postgres", "name": "shop-db", "settings": "custom", "instance_class": "db.m6g.large",
            "storage_gb": 500, "storage_type": "io2", "iops": 5000, "max_storage_gb": 1000, "multi_az": "yes",
            "backup_retention": 7, "read_replicas": 1, "backup_window": "20:00-21:00",
            "maintenance_window": "Sun:22:00-Sun:23:00", "port": 6543, "kms_key": "alias/my-db-key",
            "performance_insights": "yes", "log_exports": "yes", "iam_auth": "yes", "auto_minor_upgrade": "no",
            "deletion_protection": "yes", "final_snapshot": "yes",
            "extra_params": '{"CACertificateIdentifier": "rds-ca-rsa2048-g1"}'})
        p = step(d, "rds.create_db_instance")["params"]
        self.assertTrue(p["MultiAZ"])
        self.assertEqual((p["DBInstanceClass"], p["AllocatedStorage"], p["StorageType"], p["Iops"]),
                         ("db.m6g.large", 500, "io2", 5000))
        self.assertEqual((p["MaxAllocatedStorage"], p["BackupRetentionPeriod"], p["Port"]), (1000, 7, 6543))
        self.assertEqual(p["PreferredMaintenanceWindow"], "sun:22:00-sun:23:00")
        self.assertEqual(p["EnableCloudwatchLogsExports"], ["postgresql", "upgrade"])
        self.assertTrue(p["EnableIAMDatabaseAuthentication"] and p["EnablePerformanceInsights"] and p["DeletionProtection"])
        self.assertFalse(p["AutoMinorVersionUpgrade"])
        self.assertEqual((p["KmsKeyId"], p["CACertificateIdentifier"]), ("alias/my-db-key", "rds-ca-rsa2048-g1"))
        self.assertEqual(step(d, "ec2.authorize_security_group_ingress")["params"]["IpPermissions"][0]["FromPort"], 6543)
        order = ops(d)
        self.assertLess(order.index("rds.create_db_instance"), order.index("rds.add_tags_to_resource"))
        self.assertEqual(step(d, "rds.add_tags_to_resource")["undo"]["params"]["DeletionProtection"], False)
        self.assertIn("rds.create_db_instance_read_replica", order)
        delete = step(d, "rds.create_db_instance")["undo"]["params"]
        self.assertFalse(delete["SkipFinalSnapshot"])
        self.assertTrue(delete["FinalDBSnapshotIdentifier"].startswith("shop-db-final-"))
        self.assertTrue(any("FINAL SNAPSHOT" in n for n in d.notes))

    def test_advanced_keys_switch_to_custom(self):
        q = templates.plan("database", {"engine": "postgres", "multi_az": "yes"}, self._conn())
        self.assertEqual(next(x.default for x in q.questions if x.key == "settings"), "custom")
        self.assertEqual(q.inputs["multi_az"], "yes")
        self.assertIn("backup_retention", [x.key for x in q.questions])

    def _conn(self):
        from tests.test_recipes import conn
        return conn()

    def test_extra_params_checked_against_api_model(self):
        base = {"engine": "postgres", "settings": "custom"}
        for extra, msg in (('{"MultiAz": true}', "did you mean MultiAZ"), ('{"Engine": "mysql"}', "set by the recipe"),
                           ("not json", "JSON object"), ('{"AllocatedStorage": "big"}', "AllocatedStorage")):
            q = templates.plan("database", {**base, "extra_params": extra}, self._conn())
            self.assertIsInstance(q, TaskQuestions)
            err = next(x.error for x in q.questions if x.key == "extra_params")
            self.assertIn(msg, err)

    def test_aurora_provisioned_with_readers(self):
        d = self.build("database", {"engine": "aurora-mysql", "settings": "custom", "aurora_capacity": "provisioned",
                                    "instance_class": "db.r6g.large", "replicas": 2, "backup_retention": 3})
        inst = [s for s in d.steps if s["operation"] == "create_db_instance"]
        self.assertEqual([s["params"]["DBInstanceIdentifier"] for s in inst],
                         ["kintsugi-db-1", "kintsugi-db-2", "kintsugi-db-3"])
        self.assertTrue(all(s["params"]["DBInstanceClass"] == "db.r6g.large" for s in inst))
        self.assertNotIn("ServerlessV2ScalingConfiguration", step(d, "rds.create_db_cluster")["params"])

    def test_aurora_serverless_capacity(self):
        d = self.build("database", {"engine": "aurora-postgresql", "settings": "custom", "min_acu": "0",
                                    "max_acu": "4"})
        cfg = step(d, "rds.create_db_cluster")["params"]["ServerlessV2ScalingConfiguration"]
        self.assertEqual((cfg["MinCapacity"], cfg["MaxCapacity"]), (0.0, 4.0))
        q = templates.plan("database", {"engine": "aurora-postgresql", "settings": "custom", "min_acu": "4",
                                        "max_acu": "2"}, self._conn())
        self.assertTrue(any(x.key == "max_acu" and x.error for x in q.questions))

    def test_dynamodb_every_option(self):
        d = self.build("database", {
            "engine": "dynamodb", "name": "orders", "partition_key": "order_id", "settings": "custom",
            "billing_mode": "provisioned", "read_capacity": 10, "write_capacity": 4,
            "gsis": "byCustomer:customer_id:S; byDate:status:S:created_at:N", "stream": "NEW_AND_OLD_IMAGES",
            "ttl_attribute": "expires_at", "pitr": "yes", "deletion_protection": "yes",
            "table_class": "STANDARD_INFREQUENT_ACCESS", "kms_key": "alias/orders"})
        self.assertEqual(ops(d), ["dynamodb.create_table", "dynamodb.tag_resource", "dynamodb.update_time_to_live",
                                  "dynamodb.update_continuous_backups"])
        p = d.steps[0]["params"]
        self.assertEqual(p["BillingMode"], "PROVISIONED")
        self.assertEqual(len(p["GlobalSecondaryIndexes"]), 2)
        self.assertEqual({a["AttributeName"] for a in p["AttributeDefinitions"]},
                         {"order_id", "customer_id", "status", "created_at"})
        self.assertEqual(p["StreamSpecification"]["StreamViewType"], "NEW_AND_OLD_IMAGES")
        self.assertEqual(p["SSESpecification"]["KMSMasterKeyId"], "alias/orders")
        self.assertTrue(p["DeletionProtectionEnabled"])
        self.assertEqual(d.steps[1]["undo"]["operation"], "update_table")

    def test_bad_gsi_rejected(self):
        q = templates.plan("database", {"engine": "dynamodb", "partition_key": "id", "settings": "custom",
                                        "gsis": "x:only_two"}, self._conn())
        self.assertTrue(any(x.key == "gsis" and x.error for x in q.questions))

    def test_valkey_redis_memcached(self):
        d = self.build("database", {"engine": "valkey", "name": "cache"})
        rg = step(d, "elasticache.create_replication_group")["params"]
        self.assertEqual((rg["Engine"], rg["NumCacheClusters"], rg["TransitEncryptionEnabled"]), ("valkey", 1, True))
        d = self.build("database", {"engine": "redis", "name": "cache", "settings": "custom", "replicas": 2,
                                    "multi_az": "yes", "backup_retention": 5, "final_snapshot": "yes"})
        rg = step(d, "elasticache.create_replication_group")
        self.assertEqual((rg["params"]["NumCacheClusters"], rg["params"]["MultiAZEnabled"],
                          rg["params"]["SnapshotRetentionLimit"]), (3, True, 5))
        self.assertIn("FinalSnapshotIdentifier", rg["undo"]["params"])
        d = self.build("database", {"engine": "memcached", "name": "mc", "settings": "custom", "cache_nodes": 3})
        cc = step(d, "elasticache.create_cache_cluster")["params"]
        self.assertEqual((cc["Engine"], cc["NumCacheNodes"], cc["AZMode"]), ("memcached", 3, "cross-az"))

    def test_cache_multi_az_needs_replica(self):
        q = templates.plan("database", {"engine": "redis", "settings": "custom", "replicas": 0, "multi_az": "yes"},
                           self._conn())
        self.assertTrue(any(x.key == "multi_az" and "replica" in x.error for x in q.questions))

    def test_docdb_custom(self):
        d = self.build("database", {"engine": "docdb", "settings": "custom", "replicas": 1, "log_exports": "yes",
                                    "deletion_protection": "yes"})
        self.assertEqual(len([s for s in d.steps if s["operation"] == "create_db_instance"]), 2)
        self.assertEqual(step(d, "docdb.create_db_cluster")["params"]["EnableCloudwatchLogsExports"], ["audit", "profiler"])
        self.assertIn("docdb.add_tags_to_resource", ops(d))

    def test_new_engine_words_and_routes(self):
        self.assertEqual(recipes.engine_from_text("SQL Server Enterprise please"), "sqlserver-ee")
        self.assertEqual(recipes.engine_from_text("a valkey cache"), "valkey")
        self.assertEqual(recipes.engine_from_text("memcached"), "memcached")
        self.assertEqual(recipes.engine_from_text("oracle enterprise"), "oracle-ee")
        self.assertEqual(router.route("create a memcached cluster"),
                         ("plan_task", {"template": "database", "inputs": {"engine": "memcached"}}))

    def test_custom_class_must_look_valid(self):
        q = templates.plan("database", {"engine": "postgres", "settings": "custom", "instance_class": "huge"},
                           self._conn())
        self.assertTrue(any(x.key == "instance_class" and x.error for x in q.questions))
        d = self.build("database", {"engine": "mysql", "settings": "custom", "instance_class": "db.m7g.large"})
        self.assertEqual(step(d, "rds.create_db_instance")["params"]["DBInstanceClass"], "db.m7g.large")

    def test_extra_validated_again_at_save(self):
        d = self.build("database", {"engine": "postgres", "settings": "custom",
                                    "extra_params": json.dumps({"StorageThroughput": 500})})
        scripts.validate_steps(d.steps)
        self.assertEqual(step(d, "rds.create_db_instance")["params"]["StorageThroughput"], 500)
