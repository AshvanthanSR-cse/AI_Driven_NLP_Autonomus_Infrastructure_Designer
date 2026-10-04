"""Fake AWS clients and connection for offline tests. No network, no credentials."""
from datetime import datetime, timezone

ACCOUNT = "123456789012"


def lambda_arn(name: str) -> str:
    return f"arn:aws:lambda:ap-south-1:{ACCOUNT}:function:{name}"


class _NoPaginate:
    def can_paginate(self, op):
        return False


class FakeEvents(_NoPaginate):
    """EventBridge with the acceptance-test-1 data from CLAUDE.md."""

    def __init__(self):
        self.rules = [
            {"Name": "hello-10am-ist", "ScheduleExpression": "cron(30 4 * * ? *)", "State": "ENABLED"},
            {"Name": "hello-12pm-ist", "ScheduleExpression": "cron(30 6 * * ? *)", "State": "ENABLED"},
            {"Name": "hello-0830-ist", "ScheduleExpression": "cron(0 3 * * ? *)", "State": "ENABLED"},
            {"Name": "hello-hourly", "ScheduleExpression": "rate(1 hour)", "State": "ENABLED"},
            {"Name": "hello-disabled", "ScheduleExpression": "cron(0 10 * * ? *)", "State": "DISABLED"},
            {"Name": "s3-events", "EventPattern": "{}", "State": "ENABLED"},              # not a schedule
            {"Name": "sns-nightly", "ScheduleExpression": "cron(0 20 * * ? *)", "State": "ENABLED"},
        ]

    def list_rules(self, NextToken=None):
        # two pages to exercise pagination
        if NextToken is None:
            return {"Rules": self.rules[:3], "NextToken": "p2"}
        return {"Rules": self.rules[3:]}

    def list_targets_by_rule(self, Rule, NextToken=None, **_):
        if Rule == "sns-nightly":
            return {"Targets": [{"Id": "1", "Arn": "arn:aws:sns:ap-south-1:123456789012:topic"}]}
        return {"Targets": [{"Id": "1", "Arn": lambda_arn("cloudai-demo-hello")}]}


class FakeScheduler(_NoPaginate):
    def list_schedules(self, NextToken=None):
        return {"Schedules": [
            {"Name": "hello-3pm-ist", "GroupName": "default", "State": "ENABLED"},
            {"Name": "report-universal", "GroupName": "default", "State": "ENABLED"},
        ]}

    def get_schedule(self, Name, GroupName):
        if Name == "hello-3pm-ist":
            return {"Name": Name, "GroupName": GroupName, "State": "ENABLED",
                    "ScheduleExpression": "cron(0 15 * * ? *)", "ScheduleExpressionTimezone": "Asia/Kolkata",
                    "Target": {"Arn": lambda_arn("cloudai-demo-hello")}}
        return {"Name": Name, "GroupName": GroupName, "State": "ENABLED",
                "ScheduleExpression": "cron(0 18 ? * MON-FRI *)", "ScheduleExpressionTimezone": "Asia/Kolkata",
                "Target": {"Arn": "arn:aws:scheduler:::aws-sdk:lambda:invoke",
                           "Input": '{"FunctionName": "daily-report"}'}}


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return iter(self.pages(**kwargs))


class FakeEc2:
    def __init__(self, instances):
        self.instances = instances
        self.calls = []

    def _match(self, Filters=None):
        out = []
        for i in self.instances:
            ok = True
            for f in Filters or []:
                if f["Name"] == "instance-id":
                    ok &= i["InstanceId"] in f["Values"]
                elif f["Name"] == "tag:Name":
                    ok &= any(t["Key"] == "Name" and t["Value"] in f["Values"] for t in i.get("Tags", []))
                elif f["Name"] == "instance-state-name":
                    ok &= i["State"]["Name"] in f["Values"]
            if ok:
                out.append(i)
        return out

    def get_paginator(self, op):
        assert op == "describe_instances"
        return FakePaginator(lambda Filters=None: [{"Reservations": [{"Instances": self._match(Filters)}]}])

    def stop_instances(self, InstanceIds):
        self.calls.append(("stop", InstanceIds))
        return {"StoppingInstances": [{"InstanceId": InstanceIds[0], "PreviousState": {"Name": "running"},
                                       "CurrentState": {"Name": "stopping"}}]}

    def start_instances(self, InstanceIds):
        self.calls.append(("start", InstanceIds))
        return {"StartingInstances": [{"InstanceId": InstanceIds[0], "PreviousState": {"Name": "stopped"},
                                       "CurrentState": {"Name": "pending"}}]}


def instance(iid, name, state, env=None):
    tags = [{"Key": "Name", "Value": name}]
    if env:
        tags.append({"Key": "Env", "Value": env})
    return {"InstanceId": iid, "State": {"Name": state}, "InstanceType": "t3.micro", "Tags": tags,
            "LaunchTime": datetime(2026, 10, 1, 4, 30, tzinfo=timezone.utc), "PublicIpAddress": "1.2.3.4"}


DEMO_INSTANCES = [
    instance("i-0aaaaaaaaaaaaaaa1", "web-demo", "running", env="demo"),
    instance("i-0bbbbbbbbbbbbbbb2", "prod-db", "running"),
    instance("i-0ccccccccccccccc3", "stopped-demo", "stopped", env="demo"),
]


class FakeConn:
    """Stands in for AwsConnection; records which purpose (identity) each client was requested with."""

    def __init__(self, clients: dict):
        self.owner = "tester"
        self.clients = clients
        self.requested = []

    def client(self, service, purpose="read", region=None):
        self.requested.append((service, purpose))
        return self.clients[service]
