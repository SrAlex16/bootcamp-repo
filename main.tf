// 0. Configuración del perfil de instancia para SSM
resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "ssm-instance-profile"
  role = "ROL-SSM"  // Rol preexistente que tiene permisos para SSM

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

//0.1. Configuración del proveedor de AWS
provider "aws" {
  region = "us-east-1"  // Configura la región adecuada
}

// 1. VPC con Subnets Privadas y Públicas en Diferentes Zonas de Disponibilidad
// 1.1- Creamos el VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
     }
}

// 1.2- Crear Subnets Privadas y Públicas en dos AZ
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1a"

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-east-1b"

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

resource "aws_eip" "nat" {
  # Sin el argumento `vpc`

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

// 1.3- Internet Gateway y NAT Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

// Tabla de rutas para la red pública
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public-route-table"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

// Asociar las subnets públicas con la tabla de rutas
resource "aws_route_table_association" "public_a_association" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b_association" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

// Crear una tabla de rutas para las subnets privadas
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "private-route-table"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

// Asociar la tabla de rutas privada con las subnets privadas
resource "aws_route_table_association" "private_a_association" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b_association" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

// Asignar la tabla de rutas privada como la principal de la VPC
resource "aws_main_route_table_association" "private_as_main" {
  vpc_id         = aws_vpc.main.id
  route_table_id = aws_route_table.private.id
}

// Load Balancer Externo
resource "aws_lb" "external_lb" {
  name               = "app-external-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_external.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  enable_deletion_protection = false  # Puedes activarlo si lo necesitas

  tags = {
    Name = "app-external-lb"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

resource "aws_route53_zone" "internal" {
  name = "labAle.com"

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

resource "aws_route53_record" "app_record" {
  zone_id = aws_route53_zone.internal.id
  name    = "labAle.com"
  type    = "A"
  alias {
    name                   = aws_lb.external_lb.dns_name
    zone_id                = aws_lb.external_lb.zone_id  # Correcto
    evaluate_target_health = true
  }
}

// Load Balancer Interno
resource "aws_lb" "internal_lb" {
  name               = "app-internal-lb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_internal.id]
  subnets            = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

// Base de datos RDS para PostgreSQL
resource "aws_db_instance" "default" {
  identifier            = "joomla-db"
  engine               = "postgres"
  engine_version       = "16.3"
  instance_class       = "db.t3.micro"  //esta versión no es compatible con t2.micro y versiones anteriores dan error
  allocated_storage     = 20
  storage_type         = "gp2"
  username             = var.db_username
  password             = var.db_password
  db_name              = "joomla"
  skip_final_snapshot  = true
  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name = aws_db_subnet_group.default.name

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

// Grupo de subnets para RDS
resource "aws_db_subnet_group" "default" {
  name       = "joomla-db-subnet-group"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = {
    Name = "joomla-db-subnet-group"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

// Crear un EFS
resource "aws_efs_file_system" "joomla" {
  creation_token = "joomla-efs"
  tags = {
    Name = "joomla-efs"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

// Mount targets para EFS
resource "aws_efs_mount_target" "private_a" {
  file_system_id = aws_efs_file_system.joomla.id
  subnet_id      = aws_subnet.private_a.id
}

resource "aws_efs_mount_target" "private_b" {
  file_system_id = aws_efs_file_system.joomla.id
  subnet_id      = aws_subnet.private_b.id
}

// Instancias EC2 con Apache
resource "aws_launch_template" "web" {
  name          = "web-app-template"
  image_id      = "ami-06b21ccaeff8cd686" // Verifica que esta AMI esté disponible o selecciona otra
  instance_type = "t2.micro"
  key_name      = "clave" // Reemplaza con tu nombre de clave

  network_interfaces {
    security_groups = [aws_security_group.web.id]
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.ssm_instance_profile.name // Asignar el perfil de instancia SSM
  }

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

// Auto Scaling Group
resource "aws_autoscaling_group" "web_asg" {
  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }

  min_size            = 1
  max_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = [aws_subnet.private_a.id, aws_subnet.private_b.id]

   target_group_arns = [
    aws_lb_target_group.external_tg_https.arn,  # Registra en el target group del LB externo
    aws_lb_target_group.internal_tg_https.arn   # Registra en el target group del LB interno
  ]

  tag {
    key                 = "Name"
    value               = "web-instance"
    propagate_at_launch = true
  }
}

// Health check para el ASG
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "scale-out"
  scaling_adjustment      = 1
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.web_asg.name
}

resource "aws_autoscaling_policy" "scale_in" {
  name                   = "scale-in"
  scaling_adjustment      = -1
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.web_asg.name
}

// Secrets Manager para gestionar secretos
resource "aws_secretsmanager_secret" "db_password" {
  name = "dbPasswordLab4_Secret_39"

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

resource "aws_secretsmanager_secret_version" "db_password_version" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    password = var.db_password
  })
}

// Distribución de CloudFront
resource "aws_cloudfront_distribution" "cdn" {
  origin {
    domain_name = "labAle.com"
    origin_id   = "app-origin"

    // Aquí se pueden especificar los puertos y la política de protocolo si fuera necesario.
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2", "TLSv1.1", "TLSv1"]  // Añadir protocolos SSL permitidos
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html" // Cambia esto según lo que desees como entrada predeterminada.

  default_cache_behavior {
    target_origin_id = "app-origin"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none" // Controla cómo se manejan las cookies
      }
    }

    viewer_protocol_policy = "redirect-to-https" // Redirige a HTTPS

    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"] // Métodos que se almacenan en caché

    min_ttl      = 0                    // TTL mínimo
    default_ttl  = 86400                // TTL predeterminado (1 día)
    max_ttl      = 31536000             // TTL máximo (1 año)
  }

  restrictions {
    geo_restriction {
      restriction_type = "none" // Cambia a "whitelist" o "blacklist" si es necesario
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true // Usa el certificado predeterminado de CloudFront
  }

  tags = {
    Name = "joomla-cdn"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

// Target Group para el Load Balancer Externo (HTTPS - puerto 443)
resource "aws_lb_target_group" "external_tg_https" {
  name        = "external-tg-https"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.main.id
  target_type = "instance" // Puede ser 'instance', 'ip', o 'lambda'

  health_check {
    path                = "/"
    protocol            = "HTTPS"
    interval            = 20  // Reducido para detección más rápida
    timeout             = 6   // Aumentado para dar más tiempo a responder
    healthy_threshold   = 3   // Aumentado para evitar falsos positivos
    unhealthy_threshold = 3   // Aumentado para mayor estabilidad
  }

  tags = {
    Name = "external-tg-https"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

// Target Group para el Load Balancer Interno (HTTPS - puerto 443)
resource "aws_lb_target_group" "internal_tg_https" {
  name        = "internal-tg-https"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"

  health_check {
    path                = "/"
    protocol            = "HTTPS"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Name = "internal-tg-https"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

// Crear Security Group para el ALB Externo(Permitirá tráfico en HTTP y HTTPS)
resource "aws_security_group" "alb_external" {
  name        = "alb-external-sg"
  description = "Security group for external ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  // Permitir tráfico HTTP desde cualquier lugar
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  // Permitir tráfico HTTPS desde cualquier lugar
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { 
    Name = "alb-external-sg"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

// Crear Security Group para el ALB Interno (permitir tráfico en HTTPS)
resource "aws_security_group" "alb_internal" {
  name        = "alb-internal-sg"
  description = "Security group for internal ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  // Permitir tráfico HTTPS desde cualquier lugar
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { 
    Name = "alb-internal-sg"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

// security group de las instancias
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Security group for joomla instances"
  vpc_id      = aws_vpc.main.id

  // Permitir tráfico HTTPS (443) solo desde el Security Group del ALB
  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    security_groups  = [aws_security_group.alb_external.id]  // Permitir tráfico HTTPS solo desde el SG del ALB externo
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

//security grouo RDS
resource "aws_security_group" "db" {
  name        = "db-security-group"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id  # Referencia a la VPC que ya has creado

  ingress {
    from_port   = 5432  # Puerto por defecto para PostgreSQL
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.web.id]  # Permitir tráfico solo desde web-sg
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Permitir todo el tráfico saliente
  }

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

# Certificado desde archivos en el sistema local
resource "aws_acm_certificate" "Certificado_web" {
  certificate_body = file("certificate.pem")  # Certificado ya existente
  private_key      = file("key.pem")          # Clave privada asociada al certificado

  tags = {
    Name = "joomla-cdn"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

// Listener en el puerto 80 para el Load Balancer Externo
resource "aws_lb_listener" "external_http" {
  load_balancer_arn = aws_lb.external_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      status_code = 200
      content_type = "text/plain"
      message_body = "OK"
    }
  }

  tags = {
    Name = "external-http-listener"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

# Listener en el puerto 443 para el Load Balancer Externo (HTTPS)
resource "aws_lb_listener" "external_https" {
  load_balancer_arn = aws_lb.external_lb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"

  # Referencia al ARN del certificado ACM para HTTPS
  certificate_arn = "arn:aws:acm:us-east-1:440744220049:certificate/6a2cb772-071f-4e9a-9b81-766de468f24c"  # Usamos el nombre correcto del recurso

  default_action {
    type = "fixed-response"
    fixed_response {
      status_code = 200
      content_type = "text/plain"
      message_body = "OK"
    }
  }

  tags = {
    Name = "external-https-listener"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

// Listener en el puerto 80 para el Load Balancer Interno
resource "aws_lb_listener" "internal_http" {
  load_balancer_arn = aws_lb.internal_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      status_code = 200
      content_type = "text/plain"
      message_body = "OK"
    }
  }

  tags = {
    Name = "internal-http-listener"
    Dev  = "Alejandro"
    Env  = "Lab4"
  }
}

//VPC Peering
//1. crear vpc de backup
resource "aws_vpc" "backup" {
  cidr_block           = "10.1.0.0/16"  // Asignar un rango CIDR diferente al de la VPC de producción
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "vpc-backup"
    Dev  = "Alejandro"
    Env  = "Backup"
  }
}

//2. Crear las subnets en la nueva VPC de Backup
// Subnet pública en la VPC de Backup
resource "aws_subnet" "backup_public_a" {
  vpc_id                  = aws_vpc.backup.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "backup-public-a"
    Dev  = "Alejandro"
    Env  = "Backup"
  }
}

// Subnet pública en la VPC de Backup
resource "aws_subnet" "backup_public_b" {
  vpc_id                  = aws_vpc.backup.id
  cidr_block              = "10.1.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "backup-public-b"
    Dev  = "Alejandro"
    Env  = "Backup"
  }
}

// Subnet privada en la VPC de Backup
resource "aws_subnet" "backup_private_a" {
  vpc_id            = aws_vpc.backup.id
  cidr_block        = "10.1.3.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "backup-private-a"
    Dev  = "Alejandro"
    Env  = "Backup"
  }
}

// Subnet privada en la VPC de Backup
resource "aws_subnet" "backup_private_b" {
  vpc_id            = aws_vpc.backup.id
  cidr_block        = "10.1.4.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "backup-private-b"
    Dev  = "Alejandro"
    Env  = "Backup"
  }
}

//3. Crear el VPC Peering entre la VPC principal y la VPC de Backup
resource "aws_vpc_peering_connection" "vpc_peering_backup" {
  vpc_id      = aws_vpc.main.id               // VPC principal
  peer_vpc_id = aws_vpc.backup.id             // VPC de Backup
  auto_accept = true                           // Aceptar automáticamente el peering

  tags = {
    Name = "vpc-peering-connection-backup"
    Dev  = "Alejandro"
    Env  = "Backup"
  }
}

//4. Configurar las rutas para permitir la comunicación entre las VPCs
// Ruta en la VPC principal para la VPC de Backup (en la tabla de rutas privada)
resource "aws_route" "vpc_peering_main_route" {
  route_table_id         = aws_route_table.private.id        // Usamos la tabla de rutas privada para tráfico entre VPCs
  destination_cidr_block = "10.1.0.0/16"
  vpc_peering_connection_id = aws_vpc_peering_connection.vpc_peering_backup.id
}

// Ruta en la VPC de Backup para la VPC principal (en la tabla de rutas privada)
resource "aws_route" "vpc_peering_backup_route" {
  route_table_id         = aws_route_table.private.id        // Usamos la tabla de rutas privada en la VPC de Backup
  destination_cidr_block = "10.1.0.0/16"
  vpc_peering_connection_id = aws_vpc_peering_connection.vpc_peering_backup.id
}

//5. Configurar seguridad para permitir el tráfico
// Security Group en la VPC de Backup para permitir tráfico desde la VPC principal
resource "aws_security_group" "backup_vpc_sg" {
  name        = "backup-vpc-sg"
  description = "Security group for Backup VPC"
  vpc_id      = aws_vpc.backup.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  // Permitir tráfico desde la VPC principal
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}

// Security Group en la VPC principal para permitir tráfico desde la VPC de Backup
resource "aws_security_group" "main_vpc_sg" {
  name        = "main-vpc-sg"
  description = "Security group for main VPC"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.1.0.0/16"]  // Permitir tráfico desde la VPC de Backup
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { 
    Name = "vpc-lab4"
    Dev = "Alejandro"
    Env = "Lab4"
  }
}