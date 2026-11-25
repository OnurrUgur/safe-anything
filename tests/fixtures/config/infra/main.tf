resource "aws_security_group_rule" "ssh" {
  from_port   = 22
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_s3_bucket_acl" "b" {
  acl = "public-read"
}
resource "aws_db_instance" "d" {
  publicly_accessible = true
  storage_encrypted   = false
}
resource "aws_db_instance" "private" {
  publicly_accessible = false
  storage_encrypted   = true # was = false
  # publicly_accessible = true
}
