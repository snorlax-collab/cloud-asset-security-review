# Dedicated scanner subnet with NACL egress denies for RFC1918 + link-local (IMDS).
# Security groups are allow-only; NACLs provide explicit deny — defense-in-depth
# alongside code-level netguard.py (see docs/THREAT_MODEL.md).

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_internet_gateway" "default" {
  filter {
    name   = "attachment.vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

locals {
  # Last /24 of the VPC CIDR — override via var.scanner_subnet_cidr if it overlaps.
  scanner_subnet_cidr = var.scanner_subnet_cidr != "" ? var.scanner_subnet_cidr : cidrsubnet(data.aws_vpc.default.cidr_block, 8, 250)
}

resource "aws_subnet" "scanner" {
  vpc_id                  = data.aws_vpc.default.id
  cidr_block              = local.scanner_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = merge(local.tags, { Name = "${local.name}-scanner" })
}

resource "aws_route_table" "scanner" {
  vpc_id = data.aws_vpc.default.id
  tags   = merge(local.tags, { Name = "${local.name}-scanner" })

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = data.aws_internet_gateway.default.id
  }
}

resource "aws_route_table_association" "scanner" {
  subnet_id      = aws_subnet.scanner.id
  route_table_id = aws_route_table.scanner.id
}

resource "aws_network_acl" "scanner" {
  vpc_id = data.aws_vpc.default.id
  subnet_ids = [aws_subnet.scanner.id]
  tags   = merge(local.tags, { Name = "${local.name}-scanner-egress-filter" })
}

# DNS (public resolvers) before RFC1918 denies — VPC DNS at .2 is RFC1918 and blocked.
resource "aws_network_acl_rule" "scanner_egress_dns_udp" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 50
  egress         = true
  protocol       = "udp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 53
  to_port        = 53
}

resource "aws_network_acl_rule" "scanner_egress_dns_tcp" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 51
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 53
  to_port        = 53
}

resource "aws_network_acl_rule" "scanner_egress_deny_rfc1918_10" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "10.0.0.0/8"
}

resource "aws_network_acl_rule" "scanner_egress_deny_rfc1918_172" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 110
  egress         = true
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "172.16.0.0/12"
}

resource "aws_network_acl_rule" "scanner_egress_deny_rfc1918_192" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 120
  egress         = true
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "192.168.0.0/16"
}

resource "aws_network_acl_rule" "scanner_egress_deny_link_local" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 130
  egress         = true
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "169.254.0.0/16"
}

resource "aws_network_acl_rule" "scanner_egress_allow_internet" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 200
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# Stateless NACL — allow return traffic on ephemeral ports (no inbound connections).
resource "aws_network_acl_rule" "scanner_ingress_ephemeral_tcp" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "scanner_ingress_ephemeral_udp" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 110
  egress         = false
  protocol       = "udp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "scanner_ingress_deny_all" {
  network_acl_id = aws_network_acl.scanner.id
  rule_number    = 200
  egress         = false
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
}
