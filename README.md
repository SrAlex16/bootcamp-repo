# Lab 4

README para Infraestructura de AWS con Terraform

Este archivo de configuración de Terraform describe la creación de una infraestructura en Amazon Web Services (AWS). La infraestructura incluye la configuración de redes, servidores EC2, bases de datos RDS, balanceadores de carga (ALB), y otros servicios asociados, todo en una VPC (Virtual Private Cloud).

A continuación, se describen los recursos definidos y los pasos para implementar esta infraestructura.
## Descripción de la Infraestructura

La infraestructura desplegada incluye los siguientes recursos:
- **VPC:** Una red privada con subredes públicas y privadas distribuidas en dos Zonas de Disponibilidad (AZ).
- **Subredes**:
    - _Públicas:_ Para el tráfico externo.
    - _Privadas:_ Para el tráfico interno y comunicación con servicios dentro de la red
- **Internet Gateway y NAT Gateway**: Para permitir la conexión a internet desde las instancias en las subredes privadas.
- **Balanceadores de Carga (ALB)**:
    - _Externo:_ Para recibir tráfico HTTPS y redirigir a las instancias EC2.
    - _Interno:_ Para manejar el tráfico entre las instancias internas.
- **Instancias EC2 con Apache y PHP**: para ejecutar aplicaciones web.
- **Auto Scaling Group:** Para gestionar el escalado automático de instancias EC2.
- **Base de datos RDS PostgreSQL:** Para manejar los datos de la aplicación.
- **EFS:** Sistema de archivos compartidos accesible desde las instancias EC2.
- **CloudFront:** Distribución CDN para mejorar el rendimiento de la entrega de contenido.
- **Security Groups:** Para controlar el acceso a las instancias EC2, ALB y la base de datos RDS.

## Requisitos previos

- **Terraform:** Asegúrese de tener Terraform instalado en su máquina.
- **AWS CLI:** Debe estar configurado con las credenciales de AWS.
- **Clave SSH:** Para acceder a las instancias EC2, debe tener una clave SSH configurada



## Estructura del proyecto

| Archivo |       Descripción                |
| :-------- |  :------------------------- |
| `main.tf` |  Definición de la infraestructura |
|variables.tf | Definición de variables
|outputs.tf | Resultados de salida
|provider.tf | Configuración del proveedor AWS
|README.md   | Este archivo

#### Configuración del Proveedor de AWS

```http
  provider "aws" {
  region = "us-east-1"  # Configura la región adecuada
}
```

#### Creación de la VPC

La VPC es configurada con un bloque CIDR de 10.0.0.0/16. Se crean subredes públicas y privadas en dos Zonas de Disponibilidad.

```http
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
}

```

#### Creación de Subredes

Se crean cuatro subredes, dos públicas y dos privadas, en dos Zonas de Disponibilidad:

```http
resource "aws_subnet" "public_a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = true
}
```

#### Configuración de NAT Gateway e Internet Gateway

Se configura un NAT Gateway para permitir a las instancias en subredes privadas acceder a internet y un Internet Gateway para el acceso de las subredes públicas.

```http
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

```

#### Balanceadores de Carga

Se configuran dos balanceadores de carga de tipo Application Load Balancer (ALB), uno para tráfico externo (HTTPS) y otro para tráfico interno.

```http
resource "aws_lb" "external_lb" {
  name = "app-external-lb"
  internal = false
  load_balancer_type = "application"
  security_groups = [aws_security_group.alb_external.id]
  subnets = [aws_subnet.public_a.id, aws_subnet.public_b.id]

```

#### Base de Datos RDS

Se crea una base de datos RDS PostgreSQL con las configuraciones adecuadas para su uso dentro de la infraestructura.

```http
resource "aws_db_instance" "default" {
  identifier = "joomla-db"
  engine = "postgres"
  engine_version = "16.3"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  storage_type = "gp2"
}


```

#### Sistema de Archivos EFS

Se crea un sistema de archivos EFS para compartir archivos entre las instancias EC2.

```http
resource "aws_efs_file_system" "joomla" {
  creation_token = "joomla-efs"
}


```

#### Instancias EC2

Se configura una plantilla de lanzamiento para las instancias EC2 con Apache y PHP instalados, para ejecutar aplicaciones web.

```http
resource "aws_launch_template" "web" {
  name = "web-app-template"
  image_id = "ami-04e0020a747461148"
  instance_type = "t2.micro"
  key_name = "clave"
  user_data = base64encode(<<EOF
#!/bin/bash
sudo su
yum update -y
yum install -y php php-mysqlnd php-xml php-gd php-mbstring php-intl php-zip php-json
yum install -y httpd
systemctl start httpd
systemctl enable httpd
systemctl restart httpd
EOF
)
}

```

#### Auto Scaling Group

Se configura un Auto Scaling Group para manejar el escalado automático de las instancias EC2.

```http
resource "aws_autoscaling_group" "web_asg" {
  launch_template {
    id = aws_launch_template.web.id
    version = "$Latest"
  }
  min_size = 2
  max_size = 3
  desired_capacity = 2
}



```

#### Configuración de CloudFront

Se configura CloudFront como distribución CDN para optimizar la entrega de contenido web.

hcl
Copiar código


```http
resource "aws_cloudfront_distribution" "cdn" {
  origin {
    domain_name = "labAle.com"
    origin_id = "app-origin"
    custom_origin_config {
      http_port = 80
      https_port = 443
      origin_protocol_policy = "https-only"
    }
  }
  enabled = true
  default_root_object = "index.html"
}



```

#### Gestión de Secretos con Secrets Manager

Se crea un Secret Manager para manejar de forma segura las contraseñas de la base de datos.

```http
resource "aws_secretsmanager_secret" "db_password" {
  name = "dbPasswordLab4_Secret_45"
}



```

## Instrucciones para Implementación

1. **Configura tus credenciales de AWS:** Asegúrate de tener las credenciales de AWS configuradas en tu sistema usando aws configure o estableciendo las variables de entorno adecuadas.

2. **Inicializa Terraform:** Ejecuta el siguiente comando para inicializar el proyecto:

```http
terraform init
```

3. **Revisa el Plan de Ejecución:** Ejecuta el siguiente comando para ver qué recursos se crearán:

```http
terraform plan
```

4. **Aplica la Configuración:** Si todo está bien, aplica la configuración de Terraform para crear la infraestructura:
```http
terraform apply
```

5. **Verifica la Infraestructura:** Una vez que Terraform haya creado todos los recursos, puedes verificar los servicios desde la consola de AWS.

## A tener en cuenta

- Asegúrate de tener los archivos del certificado (certificate.pem y key.pem) disponibles en la máquina donde estás ejecutando Terraform.
- Puedes modificar las variables de configuración según sea necesario, como los tamaños de las instancias EC2 o las configuraciones de red.
## Authors

- [@Sralex16](https://github.com/SrAlex16)

