"""Script steps that need several AWS calls with run-time lookups (core/local_steps.py lists the kinds).

  s3_objects  bulk object actions under a prefix: change storage class, restore from Glacier, delete,
              copy or move (copy keeps metadata, SSE-S3 encrypted)
  cf_delete   CloudFront: disable, wait until deployed, delete with the current ETag
  ami_delete  deregister an AMI and delete the EBS snapshots behind it
  wait_until  poll a read call until a value is reached (transit gateways, attachments ...)

Only resources Kintsugi created (tag CreatedBy=kintsugi) are deleted by cf_delete; ami_delete accepts only
AMIs owned by this account. Every action runs with the script's identity; nothing is sent to the LLM.
"""
import time

from botocore.exceptions import ClientError

from core.local_steps import ARCHIVE_CLASSES, StepError, _step_timeout, _wait_for, check_prefix


def run(step: dict, conn, purpose: str, region: str, progress=None) -> dict:
    kind = step["kind"]
    fn = {"s3_objects": _s3_objects, "cf_delete": _cf_delete, "ami_delete": _ami_delete,
          "wait_until": _wait_until}[kind]
    return fn(step, conn, purpose, region, progress or (lambda _line: None))


def _code(e: Exception) -> str:
    return getattr(e, "response", {}).get("Error", {}).get("Code", "")


def _objects(s3, bucket: str, prefix: str):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        yield from page.get("Contents", [])


def _s3_objects(step, conn, purpose, region, say):
    s3 = conn.client("s3", purpose, region)
    bucket, prefix, action = step["bucket"], check_prefix(step.get("prefix", "")), step["action"]
    sc = step.get("storage_class", "STANDARD")
    done = skipped = 0
    notes: list[str] = []
    for obj in _objects(s3, bucket, prefix):
        key, cls = obj["Key"], obj.get("StorageClass", "STANDARD")
        if action == "restore":
            if cls not in ARCHIVE_CLASSES and cls != "INTELLIGENT_TIERING":
                skipped += 1
                continue
            req = {"GlacierJobParameters": {"Tier": step.get("tier", "Standard")}}
            if cls in ARCHIVE_CLASSES:
                req["Days"] = step.get("days", 1)
            try:
                s3.restore_object(Bucket=bucket, Key=key, RestoreRequest=req)
                done += 1
            except ClientError as e:
                if _code(e) in ("RestoreAlreadyInProgress", "InvalidObjectState"):
                    skipped += 1
                    continue
                raise
        elif action == "delete":
            s3.delete_object(Bucket=bucket, Key=key)
            done += 1
        else:
            if cls in ARCHIVE_CLASSES:
                skipped += 1
                if len(notes) < 3:
                    notes.append(f"{key} is in {cls}: restore it first")
                continue
            if action == "storage_class":
                dest_bucket, dest_key = bucket, key
                if cls == sc:
                    skipped += 1
                    continue
            else:
                dest_bucket = step["dest_bucket"]
                dest_key = check_prefix(step.get("dest_prefix", "")) + key[len(prefix):].lstrip("/") \
                    if prefix else check_prefix(step.get("dest_prefix", "")) + key
            extra = {"StorageClass": sc, "MetadataDirective": "COPY", "ServerSideEncryption": "AES256"}
            s3.copy({"Bucket": bucket, "Key": key}, dest_bucket, dest_key, ExtraArgs=extra)
            if action == "move":
                s3.delete_object(Bucket=bucket, Key=key)
            done += 1
        if done and (done <= 20 or done % 50 == 0):
            say(f"  {action}: {done} object(s) so far (last: {key})")
    verb = {"storage_class": f"moved to {sc}", "restore": "restore requested", "delete": "deleted",
            "copy": f"copied to s3://{step.get('dest_bucket')}", "move": f"moved to s3://{step.get('dest_bucket')}"}
    summary = f"{done} object(s) {verb[action]}" + (f", {skipped} skipped" if skipped else "")
    if action == "restore" and done:
        summary += (f". Restored copies are ready in about {RESTORE_HOURS[step.get('tier', 'Standard')]} and stay "
                    f"for {step.get('days', 1)} day(s)")
    if notes:
        summary += ". " + "; ".join(notes)
    return {"output": {"bucket": bucket, "prefix": prefix, "count": done, "skipped": skipped}, "summary": summary}


RESTORE_HOURS = {"Expedited": "1-5 minutes (Flexible Retrieval only)", "Standard": "3-5 hours (Deep Archive: 12 h)",
                 "Bulk": "5-12 hours (Deep Archive: 48 h)"}


def _cf_delete(step, conn, purpose, region, say):
    cf = conn.client("cloudfront", purpose, region)
    did = step["distribution_id"]
    try:
        got = cf.get_distribution_config(Id=did)
    except ClientError as e:
        if _code(e) == "NoSuchDistribution":
            return {"output": {"id": did}, "summary": f"{did} was already deleted"}
        raise
    arn = cf.get_distribution(Id=did)["Distribution"]["ARN"]
    tags = {t["Key"]: t["Value"] for t in cf.list_tags_for_resource(Resource=arn).get("Tags", {}).get("Items", [])}
    if tags.get("CreatedBy") != "kintsugi":
        raise StepError(f"{did} was not created by Kintsugi (tag CreatedBy=kintsugi missing); delete it yourself")
    cfg, etag = got["DistributionConfig"], got["ETag"]
    if cfg.get("Enabled"):
        say(f"  disabling {did}...")
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=did, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    say("  waiting until the change is deployed to every edge location (often 5-15 minutes)...")
    cf.get_waiter("distribution_deployed").wait(Id=did, WaiterConfig={"Delay": 30, "MaxAttempts": 60})
    etag = cf.get_distribution_config(Id=did)["ETag"]
    cf.delete_distribution(Id=did, IfMatch=etag)
    return {"output": {"id": did}, "summary": f"CloudFront distribution {did} disabled and deleted"}


def _ami_delete(step, conn, purpose, region, say):
    ec2 = conn.client("ec2", purpose, region)
    image_id = step["image_id"]
    images = ec2.describe_images(ImageIds=[image_id], Owners=["self"]).get("Images", [])
    if not images:
        return {"output": {"image_id": image_id}, "summary": f"{image_id} not found among your own AMIs"}
    snaps = [m["Ebs"]["SnapshotId"] for m in images[0].get("BlockDeviceMappings", [])
             if m.get("Ebs", {}).get("SnapshotId")]
    ec2.deregister_image(ImageId=image_id)
    say(f"  deregistered {image_id}")
    deleted = []
    for sid in snaps:
        for attempt in range(6):
            try:
                ec2.delete_snapshot(SnapshotId=sid)
                deleted.append(sid)
                break
            except ClientError as e:
                if _code(e) == "InvalidSnapshot.InUse" and attempt < 5:
                    time.sleep(10)
                    continue
                if _code(e) == "InvalidSnapshot.NotFound":
                    break
                raise
    return {"output": {"image_id": image_id, "snapshots": deleted},
            "summary": f"{image_id} deregistered, {len(deleted)} snapshot(s) deleted"}



def _value_at(data, path: str):
    cur = data
    for part in path.split("."):
        if isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        elif isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _wait_until(step, conn, purpose, region, say):
    client = conn.client(step["service"], purpose, region)
    deadline = time.monotonic() + _step_timeout(step, 1200)
    seen = {}

    def reached():
        seen["value"] = _value_at(getattr(client, step["operation"])(**step.get("params", {})), step["path"])
        if seen["value"] in ("failed", "rejected", "deleted"):
            raise StepError(f"{step['path']} became '{seen['value']}'")
        return seen["value"] in step["equals"]
    _wait_for(reached, deadline, 15, f"{step['path']} to be {' or '.join(step['equals'])}", say)
    return {"output": {"value": seen.get("value")}, "summary": f"{step['path']} is {seen.get('value')}"}
