provider "aws" {
  region = var.region
}

resource "aws_vpc" "streaming_demo_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "streaming-demo-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.streaming_demo_vpc.id

  tags = {
    Name = "streaming-demo-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.streaming_demo_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "streaming-demo-public-rt"
  }
}

resource "aws_route_table_association" "public_1" {
  subnet_id      = aws_subnet.subnet_1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_2" {
  subnet_id      = aws_subnet.subnet_2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_subnet" "subnet_1" {
  vpc_id                  = aws_vpc.streaming_demo_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-south-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "streaming-demo-subnet-1"
  }
}

resource "aws_subnet" "subnet_2" {
  vpc_id                  = aws_vpc.streaming_demo_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "ap-south-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "streaming-demo-subnet-2"
  }
}

resource "aws_iam_instance_profile" "data_engineering_project_role" {
  name = "data-engineering-project-role"
  role = aws_iam_role.data_engineering_project_role.name
}

resource "aws_iam_role" "data_engineering_project_role" {
  name = "data-engineering-project-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_full_access" {
  role       = aws_iam_role.data_engineering_project_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "emr_full_access" {
  role       = aws_iam_role.data_engineering_project_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEMRFullAccessPolicy_v2"
}

resource "aws_iam_role_policy_attachment" "s3_full_access" {
  role       = aws_iam_role.data_engineering_project_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_instance" "kafka_server" {
  ami           = "ami-0e35ddab05955cf57"
  instance_type = "t3.large"
  key_name      = "knveyrtest"

  vpc_security_group_ids = [aws_security_group.kafka_sg.id]
  subnet_id              = aws_subnet.subnet_1.id

  iam_instance_profile = aws_iam_instance_profile.data_engineering_project_role.name

  root_block_device {
    volume_size = 32
    volume_type = "gp2"
  }

  tags = {
    Name = "kafka-server"
  }
}

resource "aws_security_group" "kafka_sg" {
  name        = "kafka-security-group"
  description = "Security group for Kafka server"
  vpc_id      = aws_vpc.streaming_demo_vpc.id

  ingress {
    description = "Kafka port"
    from_port   = 9092
    to_port     = 9092
    protocol    = "tcp"
    cidr_blocks = ["${var.my_ip}/32"]
  }

  ingress {
    description = "Kafka UI port"
    from_port   = 9021
    to_port     = 9021
    protocol    = "tcp"
    cidr_blocks = ["${var.my_ip}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "kafka-security-group"
  }
}


resource "aws_s3_bucket" "streaming_demo_project" {
  bucket = "imbg-streaming-demo-project"
}

resource "aws_iam_role" "emr_service_role" {
  name = "EMR_ServiceRole"

  assume_role_policy = jsonencode({
    Version = "2008-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "elasticmapreduce.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "emr_service_role_policy" {
  role       = aws_iam_role.emr_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEMRServicePolicy_v2"
}

resource "aws_iam_role_policy" "emr_security_group_policy" {
  name = "emr_security_group_policy"
  role = aws_iam_role.emr_service_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "emr_ec2_policy" {
  name = "emr_ec2_policy"
  role = aws_iam_role.emr_service_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:DeleteSecurityGroup",
          "ec2:CreateTags",
          "ec2:DescribeTags",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:DescribeInstanceTypes"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "emr_pass_role_policy" {
  name = "emr_pass_role_policy"
  role = aws_iam_role.emr_service_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = [
          aws_iam_role.data_engineering_project_role.arn
        ]
      }
    ]
  })
}

resource "aws_emr_cluster" "streaming_demo" {
  name          = "streaming-demo"
  release_label = "emr-7.2.0"
  applications  = ["Flink", "Hadoop", "Hive", "Zeppelin"]

  log_uri = "s3://${aws_s3_bucket.streaming_demo_project.id}/logs"

  ec2_attributes {
    subnet_id                         = aws_subnet.subnet_1.id
    emr_managed_master_security_group = aws_security_group.emr_master.id
    emr_managed_slave_security_group  = aws_security_group.emr_slave.id
    instance_profile                  = aws_iam_instance_profile.data_engineering_project_role.name
    key_name                          = "knveyrtest"
  }

  master_instance_group {
    instance_type  = "m5.xlarge"
    instance_count = 1

    ebs_config {
      size                 = "32"
      type                 = "gp2"
      volumes_per_instance = 2
    }
  }

  core_instance_group {
    instance_type  = "m4.large"
    instance_count = 2

    ebs_config {
      size                 = "32"
      type                 = "gp2"
      volumes_per_instance = 2
    }
  }

  tags = {
    for-use-with-amazon-emr-managed-policies = "true"
  }

  service_role = aws_iam_role.emr_service_role.arn

  scale_down_behavior = "TERMINATE_AT_TASK_COMPLETION"

  auto_termination_policy {
    idle_timeout = 3600
  }
}

resource "aws_security_group" "emr_master" {
  name        = "EMR-Master-SecurityGroup"
  description = "Security group for EMR master"
  vpc_id      = aws_vpc.streaming_demo_vpc.id

  # Allow all inbound traffic within the security group
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  # Allow SSH access only from your IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.my_ip}/32"]
  }

  # Allow EMR Console access only from your IP
  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["${var.my_ip}/32"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "EMR-Master-SecurityGroup"
  }
}

resource "aws_security_group" "emr_slave" {
  name        = "EMR-Slave-SecurityGroup"
  description = "Security group for EMR slave"
  vpc_id      = aws_vpc.streaming_demo_vpc.id

  # Allow all inbound traffic within the security group
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  # Allow SSH access only from your IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.my_ip}/32"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "EMR-Slave-SecurityGroup"
  }
}

resource "aws_redshiftserverless_namespace" "streaming_namespace" {
  namespace_name      = "streaming-namespace"
  admin_username      = "admin"
  admin_user_password = var.password_for_redshift_admin
}

resource "aws_redshiftserverless_workgroup" "redshift_streaming_workgroup" {
  namespace_name = aws_redshiftserverless_namespace.streaming_namespace.namespace_name
  workgroup_name = "redshift-streaming-workgroup"

  base_capacity = 32
}
