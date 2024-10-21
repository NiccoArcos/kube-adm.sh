#!/bin/bash
#Prueba para git
#Colores para la salida en consola

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NO_COLOR='\033[0m'

#Funcion para mostrar mensaje de exito

#Exito
success() {
	echo -e "${GREEN}[✔] $1${NC}"
}


#Error
error() {
    echo -e "${RED}[✖] $1${NC}"
}

#Informacion
info() {
    echo -e "${YELLOW}➜ $1${NC}"
}



#Verificar si el script se ejecuta como sudo

if [[ $EUID -ne 0 ]]; then
	error "El script debe ejecutarse como super usuario..."
	exit 1
fi


echo "=========================================================================================================="
echo "INSTALADOR Y CONFIGURADOR DE KUBEADM, KUBELET Y KUBECTL PARA CLUSTER KUBERNETES" 

#Actualizar el SO

echo "=========================================================================================================="
info "TAREA 1: ACTUALIZAR SISTEMA OPERATIVO"
info "Verificando si hay paquetes disponibles para actualizar..."

if yum check-update | grep -q "Packages"; then
	info "Las dependencias no estan actualizadas, se procede a realizar la actualizacion de las mismas..."
	yum update -y && yum upgrade -y
	if [ $? eq 0 ]; then
		success "El sistema ha sido actualizado correctamente..."
	
	else
		error "El sistema no ha podido actualizarse con éxito..."
		exit 1
		
	fi

else
	info "Las dependencias estan al dia... nada que realizar".

fi




#Cambiar el nombre del hostname para el Control Plain
echo "=========================================================================================================="
info "TAREA 2: CAMBIAR HOSTNAME Y CONFIGURAR ARCHIVO HOSTS PARA EL CLUSTER"
info "\033[4mSubtarea en ejecución: Cambio de hostname...\033[0m"
info "Nombre del host actual: $(hostname)"
nuevo_hostname="master"
sudo hostnamectl set-hostname "$nuevo_hostname"
success "Nombre del host cambiado a: $(hostname)"

#Direcciones IPs de nodos y maestros |  hostsnames al archivo /etc/hosts
info "\033[4mSubtarea en ejeución: Agregado de Hosts e IPs en archivo /etc/hosts\033[0m"

ip_addresses=("192.168.100.52" "192.168.100.53" "192.168.100.93")
hosts_names=("master" "worker01" "worker02")

agregar_hosts() {
	local ip_addres="$1"
	local host_name="$2"

	if grep -qw "$ip_addres"  /etc/hosts && grep -qw "$host_name" /etc/hosts; then
		 info " El host ${ip_address} está agregado en el archivo. Nada que hacer..."
	
	else
		echo "$ip_addres $host_name" | sudo tee -a /etc/hosts > /dev/null
		success "El Host : $host_name | De Ip Adrress: $ip_addres | fué agregado con éxito "



	fi
}	

# Iterar sobre los hosts
for i in "${!ip_addresses[@]}"; do
	agregar_hosts "${ip_addresses[$i]}" "${hosts_names[$i]}"
done



echo "==========================================================================================================" 
info "\033[1mTAREA 3: DESACTIVAR SWAP Y SELINUX\033[0m"
info "\033[4mSubtarea en ejecución: Desactivar SWAP...\033[0m"
info "Desactivando SWAP desde FSTAB..."
sed -i '/swap/s/^/#/' /etc/fstab

info Verificando...
cat /etc/fstab
info "SWAP Desactivado desde fstab."

info "Desactivando SWAP desde consola... ejecutando swapoff -a"
sudo swapoff -a 


swap_usage=$(free | awk '/Swap/{print $3}')

if [[ "$swap_usage" -eq 0 ]]; then
	success "La memoria swap fue desactivada exitosamente SWAP"
	success "La memoria swap esta consumiendo ${swap_usage}B"

else
	error "La memoria swap no fue desactivada exitosamente..."
	error "Consumo actual de memoria: ${swap_usage}MB"
	exit 1

fi


info "\033[4mSubtarea en ejecución: Desactivar SELINUX\033[0m"

config_file_selinux=/etc/selinux/config

#Verificar si la linea esta desactivada
if grep -q "^SELINUX=disabled" "$config_file_selinux"; then
	info "SELINUX se encuentra desactivado, no se ejecutarán cambios..."

else
	sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' $config_file_selinux

	sed -i 's/^SELINUX=permissive/SELINUX=disabled/' $config_file_selinux

	info "Se ha realizado el cambio del estado de SELINUX"
	info "Verificando..."
	

fi

#Verificacion de cambio de linea

if grep -q "^SELINUX=disabled" "$config_file_selinux"; then
	success "Verificación exitosa el valor de la variable ha sido cambiado"

else
	error "El valor de SELINUX no ha sido modificado con éxito"
fi



#Verificar el estado de SELINUX
selinux_status=$(sestatus)

if echo "$selinux_status" | grep -q "disabled"; then
	success "El estado de SELINUX ha sido cambiado a disabled exitosamente"

else
	error "El estado de SELINUX no ha sido cambiado con exito... Es necesario reiniciar el equipo para aplicar cambios"
fi




echo "=========================================================================================================="
info "\033[1mTAREA 4: HABILITACION DE PUERTOS TCP PARA KUBERNETES\033[0m"
info "\033[4mSubtarea en ejecución: Habilitación de puertos TCP\033[0m"

# Función para verificar si el puerto ya está habilitado en el firewall
verificar_puerto_firewall() {
    local puerto=$1
    local tipo=$2
    
    # Verificar si el puerto ya está habilitado en el firewall
    if firewall-cmd --list-ports | grep -q "$puerto/$tipo"; then
        info "El puerto $puerto/$tipo ya está habilitado en el firewall."
        return 1
    fi
    
    # Si no se encuentra el puerto habilitado
    return 0
}

# Función para verificar si el puerto está en uso en el sistema
verificar_puerto() {
    local puerto=$1
    local tipo=$2

    if [[ "$tipo" == "tcp" ]]; then
        # Verificar puertos TCP en el sistema
        if ss -tln | grep -q ":$puerto\b"; then
            info "El puerto $puerto/$tipo ya está en uso."
            return 1
        fi
    elif [[ "$tipo" == "udp" ]]; then
        # Verificar puertos UDP en el sistema
        if ss -uln | grep -q ":$puerto\b"; then
            info "El puerto $puerto/$tipo ya está en uso."
            return 1
        fi
    fi

    return 0
}

# Lista de puertos TCP
puertos_tcp=(6443 2379 2380 10250 10251 10252 10257 10259 179)

# Agregar puertos TCP
for puerto in "${puertos_tcp[@]}"; do
    # Verificar si el puerto TCP ya está habilitado en el firewall
    verificar_puerto_firewall "$puerto" "tcp"
    if [[ $? -ne 0 ]]; then
        info "No se agregará el puerto TCP: $puerto (ya está habilitado en el firewall)"
        continue
    fi

    # Verificar si el puerto TCP está en uso en el sistema
    verificar_puerto "$puerto" "tcp"
    if [[ $? -ne 0 ]]; then
        info "No se agregará el puerto TCP: $puerto (ya en uso en el sistema)"
    else
        success "Agregando puerto TCP: $puerto"
        sudo firewall-cmd --permanent --add-port="$puerto/tcp"
    fi
done

# Puerto UDP
puerto_udp=4789

# Verificar y agregar el puerto UDP
verificar_puerto_firewall "$puerto_udp" "udp"
if [[ $? -ne 0 ]]; then
    info "No se agregará el puerto UDP: $puerto_udp (ya está habilitado en el firewall)"
else
    verificar_puerto "$puerto_udp" "udp"
    if [[ $? -ne 0 ]]; then
        info "No se agregará el puerto UDP: $puerto_udp (ya en uso en el sistema)"
    else
        success "Agregando puerto UDP: $puerto_udp"
        sudo firewall-cmd --permanent --add-port="$puerto_udp/udp"
    fi
fi

# Recargar firewall para aplicar cambios
    
recargar_puertos=$(sudo firewall-cmd --reload)
success "Recargando puertos... Resultado: ${recargar_puertos}"
listar_puertos=$(sudo firewall-cmd --list-all | grep 'ports:' | sed 's/ports: //; s/forward-//g; s/source-//g' | tr ',' '\n' | grep -v '^$')

info "Todos los puertos deseados estan ya configurados"
success "Puertos TCP actuales: ${listar_puertos}"





echo "=========================================================================================================="
info "\033[1mTAREA 5: PREPARAR EL KERNEL\033[0m"
info "\033[4mSubtarea en ejecución: Modulos de K8S \033[0m"

k8s_conf=/etc/modules-load.d/k8s.conf

if [ -f "$k8s_conf" ];  then

       info "El archivo de configuración ya existe... se conserva el existente."

else
	info "El archivo de configuración no existe... se prodece a crearlo".
	cat <<EOF > /etc/modules-load.d/k8s.conf
overlay
br_netfilter	
EOF

	success "Archivo creado correctamente"
	contenido_module_k8s=$(cat "$k8s_conf")
	if [ -n "$contenido_module_k8s" ]; then
		success "El archivo contiene"
		echo "$contenido_module_k8s"
	

	fi

fi	
	

info "\033[4mSubtarea en ejecución: Configuracion de sysctl para K8S \033[0m"
k8s_sysctl=/etc/sysctl.d/k8s.conf

if [ -f "$k8s_sysctl" ]; then
	info "El archivo de configuración ya existe... se conserva el existente."

else
	info "El archivo de configuración no existe... se procede a crearlo."

	cat <<EOF > /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
	success "Archivo creado exitosamente"
	contenido_sysctl_k8s=$(cat "$k8s_sysctl")
	
	if [ -n "$contenido_sysctl_k8s" ]; then
		success "El archivo contiene:"
		echo "$contenido_sysctl_k8s"
	
	        info "Aplicando configuraciones..."
        	sudo sysctl --system
        	sysctl_system=$(sudo sysctl --system)
	fi
fi


echo "=========================================================================================================="
info "\033[1mTAREA 6 INSTALAR CONTAINERD: \033[0m"
info "\033[4mSubtarea en ejecución: Instalando yum-utils... \033[0m"

if rpm -q yum-utils > /dev/null 2>&1; then
	info "El paquete yum-utils se encuentra instalado... no se procederá a instalarlo nuevamente"

else 
	info "El paquete yum-utils no se encuentra instalado... se procederá a instalarlo"
	sudo yum install -y yum-utils
	
	if rpm -q yum-utils > /dev/null 2>&1; then
		success "El paquete yum-utils fue instalado exitosamente"
	fi
fi



info "\033[4mSubtarea en ejecución: Configurando repositorio Docker... \033[0m"
info "Verificando si el repositorio ya esta cargado en /etc/yum.repos.d/..."

ver_directorio_repo=$(ls /etc/yum.repos.d)
repo_docker=/etc/yum.repos.d/docker-ce.repo

	
if [ -f "$repo_docker" ]; then
    info "El archivo 'docker-ce.repo' ya existe en el directorio, se conserva el existente."

else
    info "El archivo 'docker-ce.repo' no existe en el directorio, se procede a crearlo"
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

    # Bucle para esperar hasta que el archivo aparezca
    while [ ! -f /etc/yum.repos.d/docker-ce.repo ]; do
        sleep 5
    done

    info "Verificando si el archivo se encuentra en el directorio..."
    success "El archivo se encuentra en el directorio: /etc/yum.repos.d/$(ls /etc/yum.repos.d | grep docker-ce.repo)"

fi


info "\033[4mSubtarea en ejecución: Instalación de Containerd... \033[0m"
info "Verificando si containerd esta instalado..."

if rpm -q containerd.io > /dev/null 2>&1; then
	info "El container runtime "containerd" se encuentra instalado en el sistema. No se ejecutará acción de instalación."

else
	info "El container runtime "containerd" no se encuentra instalado... se procederá a instalarlo."
	yum install -y containerd

	if rpm -q containerd.io > /dev/null 2>&1; then
		success "El container runtime fue instalado con éxito..."
	fi

fi
	


info "\033[4mSubtarea en ejecución: Configuración de config.toml... \033[0m"
config_toml=/etc/containerd/config.toml

sudo  cp "$config_toml" /etc/containerd/config.toml.bkp
sudo containerd config default | sudo tee /etc/containerd/config.toml > /dev/null



# Verificar si la línea SystemdCgroup existe, ignorando espacios e indentaciones
if grep -q "^[[:space:]]*SystemdCgroup" "$config_toml"; then
    info "➜ La línea 'SystemdCgroup' existe en el archivo, cambiando su valor de false por true..."
    
    sudo sed -i 's/^\([[:space:]]*SystemdCgroup *= *\).*/\1true/' "$config_toml"
    
    # Visualizar el valor actualizado de la línea SystemdCgroup
    visualizar_SystemdCgroup=$(grep "^[[:space:]]*SystemdCgroup" "$config_toml")

    # Mostrar el valor actualizado
    success "Visualizando valor de la variable: $visualizar_SystemdCgroup"
else
    error "La línea 'SystemdCgroup' no se encontró en el archivo."
fi


info "Habilitando y reinciando containerd..."

systemctl enable containerd
systemctl restart containerd

estado_gral=$(systemctl status containerd)
estado_container=$(echo "$estado_gral" | grep -i "Active:")

if echo "$estado_container" | grep -q "active"; then
	success "El container runtime se encuentra activo y habilitado"

else
	error "el container runtime no se encuentra activo"

fi


    
















































