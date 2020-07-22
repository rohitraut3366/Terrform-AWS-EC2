provider "aws" {
  region     = "ap-south-1"
  profile    = "RDR"
}
resource "tls_private_key" "Key" {
  algorithm   = "RSA"
  rsa_bits = "2048"
}
resource "aws_key_pair" "key_gen" {
  key_name   = "key123"
  public_key = tls_private_key.Key.public_key_openssh
}

resource "local_file" "keystore" {
    content     = tls_private_key.Key.private_key_pem
    filename = "key123.pem"
}
#create security group
resource "aws_security_group" "Security_Group" {
  name        = "security"
  description = "firewall allowing port 22 and 80"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "b" {
  bucket = "mynewbucket123123"
  acl    = "private"
  force_destroy  = true
}
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
}
data "aws_iam_policy_document" "distribution" {
  statement {
    actions = ["s3:GetObject"]
    principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
    resources = ["${aws_s3_bucket.b.arn}/*"]
  }
}
resource "aws_s3_bucket_policy" "web_distribution" {
  bucket = aws_s3_bucket.b.id
  policy = data.aws_iam_policy_document.distribution.json
}

locals {
  depends_on = [
      aws_cloudfront_origin_access_identity.origin_access_identity
  ]
  s3_origin_id = aws_s3_bucket.b.id
}
#aws cloud distribution
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled     = true

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  restrictions {
      geo_restriction {
        restriction_type = "none"
      }
    }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
output "cd"{
  value = aws_cloudfront_distribution.s3_distribution.domain_name
}
resource "aws_instance" "web" {
  depends_on = [
      aws_security_group.Security_Group
  ]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name  =  aws_key_pair.key_gen.key_name
  security_groups = ["${aws_security_group.Security_Group.name}"]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.Key.private_key_pem
    host     = aws_instance.web.public_ip
  }
  tags = {
    Name = "terraform os"
  }
}
resource "aws_ebs_volume" "ebs3" {
  availability_zone = aws_instance.web.availability_zone
  size              = 1

  tags = {
    Name = "ebs04"
  }
}
resource "aws_volume_attachment" "ebs_att" {
  depends_on =[
    aws_instance.web,
    aws_ebs_volume.ebs3
   ]
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.ebs3.id
  instance_id = aws_instance.web.id
  force_detach  = true
}

resource "null_resource" "cluster" {
  depends_on = [
    aws_instance.web
  ]
   connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.Key.private_key_pem
    host     = aws_instance.web.public_ip
  }
    provisioner "remote-exec" {
        inline = [
          "sudo yum install git httpd php -y",
          "sudo systemctl start httpd",
          "sudo systemctl enable httpd"
        ]
      }
}

resource "null_resource" "cluster123" {
  depends_on = [
    aws_volume_attachment.ebs_att
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.Key.private_key_pem
    host     = aws_instance.web.public_ip
  }
  provisioner "remote-exec" {
    inline = [
          "sudo mkfs.ext4 /dev/sdh",
          "sudo mount  /dev/xvdh  /var/www/html",
          "sudo rm -rf /var/www/html/*",
          "sudo git clone https://github.com/rohitraut3366/mulicloud.git /var/www/html/"
        ]
    }
}
output "ip2"{
    value =  aws_instance.web.public_ip
}
