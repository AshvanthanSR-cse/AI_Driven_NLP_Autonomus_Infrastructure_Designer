ALTER TABLE aws_credentials ADD COLUMN IF NOT EXISTS iam_user TEXT;
ALTER TABLE aws_credentials ADD COLUMN IF NOT EXISTS principal_arn TEXT;
