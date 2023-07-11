vim /etc/hosts
	127.0.1.1 kube-admin1
nslookup 127.0.1.1
vim /etc/hostname
	kube-worker3
hostname kube-admin1
su - root
vim /etc/ssh/sshd_config
	PermitRootLogin yes
systemctl restart ssh || systemctl restart sshd
systemctl status ssh || systemctl status sshd
ssh localhost
ip a
vim /etc/netplan/00-installer-config.yaml
	ips & interfaces
netplan --debug apply
ip a

vim /root/.ssh/authorized_keys
	ssh-ed25519 ... root@kube-template1
	ssh-ed25519 ... root@kube-admin1
	ssh-ed25519 ... root@kube-master1
	ssh-ed25519 ... root@kube-master2
	ssh-ed25519 ... root@kube-master3
	ssh-ed25519 ... root@kube-worker1
	ssh-ed25519 ... root@kube-worker2
	ssh-ed25519 ... root@kube-worker3

for sname in template1 admin1 master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "echo ------------; hostname; cat /etc/hosts | grep template; sed -i 's/template/template1/' /etc/hosts; cat /etc/hosts | grep template"; done


#создаем ФС для для данных и NFS-шары на admin1, устанавливаем и настраиваем NFS сервер
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
df -h
lsblk
pvs
vgs
lvs
#parted /dev/sdb
#mktable msdos
#quit
pvcreate /dev/sdb
vgcreate data-vg /dev/sdb
lvcreate -l 100%FREE data-vg -n data-lv
pvs
vgs
lvs
mkfs.xfs /dev/mapper/data--vg-data--lv
mkdir /data
#comment exist /data in /etc/fstab
echo '/dev/mapper/data--vg-data--lv /data xfs defaults 0 1' >> /etc/fstab
mount /data
df -h

df -h
lsblk
pvs
vgs
lvs
pvcreate /dev/sdc
vgcreate nfs-vg /dev/sdc
lvcreate -l 100%FREE nfs-vg -n nfs-lv
pvs
vgs
lvs
mkfs.xfs /dev/mapper/nfs--vg-nfs--lv
mkdir /nfs
echo '/dev/mapper/nfs--vg-nfs--lv /nfs xfs defaults 0 1' >> /etc/fstab
mount /nfs
df -h

grep ^ /etc/apt/sources.list /etc/apt/sources.list.d/*
apt update
apt list --upgradable
#apt upgrade
#reboot
unane -a
apt install nfs-kernel-server
rpcinfo -p | grep nfs
cat /proc/filesystems | grep nfs
modprobe nfs
cat /proc/filesystems | grep nfs
systemctl enable nfs-server
systemctl status nfs-server
mkdir /nfs/masters
mkdir /nfs/workers
mkdir /nfs/cluster
echo '/nfs/masters kube-master1(rw,sync,no_subtree_check) kube-master2(rw,sync,no_subtree_check) kube-master3(rw,sync,no_subtree_check)' >> /etc/exports
echo '/nfs/workers kube-worker1(rw,sync,no_subtree_check) kube-worker2(rw,sync,no_subtree_check) kube-worker3(rw,sync,no_subtree_check)' >> /etc/exports
echo '/nfs/cluster kube-master1(rw,sync,no_subtree_check,no_root_squash) kube-master2(rw,sync,no_subtree_check,no_root_squash) kube-master3(rw,sync,no_subtree_check,no_root_squash) kube-worker1(rw,sync,no_subtree_check,no_root_squash) kube-worker2(rw,sync,no_subtree_check,no_root_squash) kube-worker3(rw,sync,no_subtree_check,no_root_squash)' >> /etc/exports
exportfs -arv
ufw status
ufw allow 111
ufw allow 2049
"; done


#создаем ФС для данных на master1 master2 master3 worker1 worker2 worker3, устанавливаем и настраиваем NFS клиент
for sname in master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "
echo ------------; hostname
df -h
lsblk
pvs
vgs
lvs
#parted /dev/sdb
#mktable msdos
#quit
pvcreate /dev/sdb
vgcreate data-vg /dev/sdb
lvcreate -l 100%FREE data-vg -n data-lv
pvs
vgs
lvs
mkfs.xfs /dev/mapper/data--vg-data--lv
mkdir /data
#comment exist /data in /etc/fstab
echo '/dev/mapper/data--vg-data--lv /data xfs defaults 0 0' >> /etc/fstab
mount /data
df -h

grep ^ /etc/apt/sources.list /etc/apt/sources.list.d/*
apt update
apt list --upgradable
#apt upgrade
#reboot
unane -a
apt install nfs-common
mkdir -p /nfs
mkdir -p /nfs/cluster
echo 'kube-admin1:/nfs/cluster /nfs/cluster nfs4 defaults,nofail 0 0' >> /etc/fstab
mount /nfs/cluster
if [[ $sname in kube-master1 kube-master2 kube-master3 ]]; then
mkdir -p /nfs/masters
echo 'kube-admin1:/nfs/masters /nfs/masters nfs4 defaults,nofail 0 0' >> /etc/fstab
mount /nfs/masters
elsif [[ $sname in kube-worker1 kube-worker2 kube-worker3 ]]; then
mkdir -p /nfs/workers
echo 'kube-admin1:/nfs/workers /nfs/workers nfs4 defaults,nofail 0 0' >> /etc/fstab
mount /nfs/workers
fi
cat /etc/fstab
df -h | grep -v /run/containerd/ | grep -v /var/lib/kubelet/
"; done


# прописываем локальный DNS
for ip in 229 220 221 224 223 225 226 227
do
ssh root@X.X.X.$ip '
echo ------------
hostname
echo "
X.X.X.229 kube-template1
X.X.X.220 kube-admin1
X.X.X.221 kube-master1
X.X.X.224 kube-master2
X.X.X.223 kube-master3
X.X.X.225 kube-worker1
X.X.X.226 kube-worker2
X.X.X.227 kube-worker3" >> /etc/hosts
cat /etc/hosts
'
done


# создаем безпарольное подключение между всеми узлами
for sname in template1 admin1 master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname 'ssh-keygen -t ed25519; cat /root/.ssh/id_ed25519.pub' >> /root/.ssh/authorized_keys; done


# реплицируем полученный ключ на все ноды кластера
for sname in template1 master1 master2 master3 worker1 worker2 worker3; do scp /root/.ssh/authorized_keys root@kube-$sname:/root/.ssh/; done


# устанавливаем системные пакеты
for sname in template1 admin1 master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname '
echo ------------; hostname
apt update
apt list --upgradable
#apt upgrade
apt install inetutils-traceroute ntpdate ntp mc
date
systemctl status ntp
systemctl restart ntp
systemctl status ntp
date
timedatectl list-timezones
timedatectl set-timezone Europe/Moscow
timedatectl
'
done


# удаляем своп на мастерах и воркерах
for sname in master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "echo ------------; hostname; swapon -s; swapoff -a; swapon -s; sed -i 's/\/swap.img/# \/swap.img/' /etc/fstab; cat /etc/fstab"; done


# сетевые настройки
for sname in master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "
echo ------------; hostname
cat <<EOF | tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

modprobe overlay
modprobe br_netfilter

# sysctl params required by setup, params persist across reboots
cat <<EOF | tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

# Apply sysctl params without reboot
sysctl --system

lsmod | grep br_netfilter
lsmod | grep overlay

sysctl net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables net.ipv4.ip_forward
"; done


# устанавливаем container runtime
for sname in master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "
echo ------------; hostname
OS=xUbuntu_22.04
VERSION=1.27
rm /usr/share/keyrings/libcontainers-*
rm /etc/apt/sources.list.d/devel:kubic:libcontainers:stable*
echo 'deb http://deb.debian.org/debian buster-backports main' > /etc/apt/sources.list.d/backports.list
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ...
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ...
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ...

#echo 'deb [signed-by=/usr/share/keyrings/libcontainers-archive-keyring.gpg trusted=yes] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/ /' > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
#echo 'deb [signed-by=/usr/share/keyrings/libcontainers-crio-archive-keyring.gpg trusted=yes] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/ /' > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:$VERSION.list
echo 'deb [signed-by=/usr/share/keyrings/libcontainers-archive-keyring.gpg] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_22.04/ /' > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
echo 'deb [signed-by=/usr/share/keyrings/libcontainers-crio-archive-keyring.gpg] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/1.27/xUbuntu_22.04/ /' > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:1.27.list
apt update
apt install -y -t buster-backports libseccomp2 || apt update -y -t buster-backports libseccomp2
#apt upgrade

mkdir -p /usr/share/keyrings
#curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/Release.key | gpg --dearmor -o /usr/share/keyrings/libcontainers-archive-keyring.gpg
#curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/Release.key | gpg --dearmor -o /usr/share/keyrings/libcontainers-crio-archive-keyring.gpg
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_22.04/Release.key | gpg --dearmor -o /usr/share/keyrings/libcontainers-archive-keyring.gpg
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/1.27/xUbuntu_22.04/Release.key | gpg --dearmor -o /usr/share/keyrings/libcontainers-crio-archive-keyring.gpg

apt update
apt install -y git wget curl containerd cri-o cri-o-runc

mkdir -p /var/lib/crio
systemctl enable crio
systemctl start crio
systemctl status crio

groupadd docker
usermod -aG docker $USER

#VER=$(curl -s https://api.github.com/repos/Mirantis/cri-dockerd/releases/latest|grep tag_name | cut -d '"' -f 4|sed 's/v//g')
VER=0.3.3
#wget https://github.com/Mirantis/cri-dockerd/releases/download/v${VER}/cri-dockerd-${VER}.amd64.tgz
wget https://github.com/Mirantis/cri-dockerd/releases/download/v0.3.3/cri-dockerd-0.3.3.amd64.tgz

#tar xvf cri-dockerd-${VER}.amd64.tgz
tar xvf cri-dockerd-0.3.3.amd64.tgz
mv cri-dockerd/cri-dockerd /usr/local/bin/
cri-dockerd --version
rm -r cri-dockerd

wget https://raw.githubusercontent.com/Mirantis/cri-dockerd/master/packaging/systemd/cri-docker.service
wget https://raw.githubusercontent.com/Mirantis/cri-dockerd/master/packaging/systemd/cri-docker.socket
mv cri-docker.socket cri-docker.service /etc/systemd/system/
sed -i -e 's,/usr/bin/cri-dockerd,/usr/local/bin/cri-dockerd,' /etc/systemd/system/cri-docker.service

systemctl enable cri-docker.service
systemctl status cri-docker.service

systemctl enable cri-docker.socket
systemctl start cri-docker.socket
systemctl status cri-docker.socket

ls -la /var/run/containerd/containerd.sock /var/run/crio/crio.sock /var/run/cri-dockerd.sock
apt list --upgradable
"; done


# устанавливаем kubeadm, kubelet, kubectl
for sname in admin1 master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "
echo ------------; hostname
apt update
apt install -y apt-transport-https ca-certificates curl
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-archive-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-archive-keyring.gpg trusted=yes] https://apt.kubernetes.io/ kubernetes-xenial main' | sudo tee /etc/apt/sources.list.d/kubernetes.list
apt update
apt install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl
"; done


# настраиваем containerd crio cri-dockerd
for sname in master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "
echo ------------; hostname
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i s/'            SystemdCgroup = false'/'            SystemdCgroup = true'/ /etc/containerd/config.toml
cat /etc/containerd/config.toml | grep 'SystemdCgroup'
cat /etc/containerd/config.toml | grep 'sandbox_image'
systemctl daemon-reload
systemctl restart containerd
systemctl status containerd
ls -la /run/containerd/containerd.sock

sed -i s/'# pause_image = '/'pause_image = '/ /etc/crio/crio.conf
cat /etc/crio/crio.conf | grep pause_image
echo '[crio.runtime]
conmon_cgroup = \"pod\"
cgroup_manager = \"cgroupfs\"' > /etc/crio/crio.conf.d/02-cgroup-manager.conf
cat /etc/crio/crio.conf.d/02-cgroup-manager.conf
systemctl restart crio
systemctl stop crio
systemctl disable crio
systemctl status crio
ls -la /var/run/crio/crio.sock

systemctl restart cri-docker.socket
systemctl stop cri-docker.socket
systemctl disable cri-docker.socket
systemctl status cri-docker.socket
systemctl stop cri-docker.service
systemctl disable cri-docker.service
systemctl status cri-docker.service
ls -la /run/cri-dockerd.sock
"; done


# установим CNI
for sname in master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname '
echo ------------; hostname
set -eu -o pipefail
apt install -y golang-go
CNI_COMMIT="plugins"
CNI_DIR=${DESTDIR:=""}/opt/cni
CNI_CONFIG_DIR=${DESTDIR}/etc/cni/net.d

# e2e and Cirrus will fail with "sudo: command not found"
SUDO=""
if (( $EUID != 0 )); then
    SUDO="sudo"
fi

TMPROOT=$(mktemp -d)
git clone https://github.com/containernetworking/plugins.git "${TMPROOT}"/plugins
pushd "${TMPROOT}"/plugins
git checkout "$CNI_COMMIT"
./build_linux.sh
$SUDO mkdir -p $CNI_DIR
$SUDO cp -r ./bin $CNI_DIR
$SUDO mkdir -p $CNI_CONFIG_DIR
$SUDO cat << EOF | $SUDO tee $CNI_CONFIG_DIR/10-containerd-net.conflist
{
  "cniVersion": "1.0.0",
  "name": "containerd-net",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni0",
      "isGateway": true,
      "ipMasq": true,
      "promiscMode": true,
      "ipam": {
        "type": "host-local",
        "ranges": [
          [{
            "subnet": "X.X.X.0/16"
          }],
          [{
            "subnet": "2001:4860:4860::/64"
          }]
        ],
        "routes": [
          { "dst": "0.0.0.0/0" },
          { "dst": "::/0" }
        ]
      }
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    }
  ]
}
EOF

popd
rm -fR "${TMPROOT}"
'; done


# добавляем запись DNS об IP LoadBalancer-а
for sname in admin1 master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "
echo ------------; hostname
echo 'X.X.X.222 kube-vip1' >> /etc/hosts
cat /etc/hosts
"; done


# настраиваем LoadBalancer для control plane node
for sname in master1 master2 master3; do ssh root@kube-$sname '

# !!!!!!!!!! set sname if only one host s script

echo ------------; hostname
kubeadm reset --cri-socket=unix:///var/run/containerd/containerd.sock

if [[ $sname = "master1" ]]
then
  STATE="MASTER"
  PRIORITY="101"
else
  STATE="BACKUP"
  PRIORITY="100"
fi

INTERFACE="ens4"
ROUTER_ID="51"
AUTH_PASS="42"
APISERVER_VIP="X.X.X.222"
#APISERVER_VIP="kube-vip1"
APISERVER_DEST_PORT="8080"
APISERVER_SRC_PORT="6443"
HOST1_ID="master1"
HOST1_ADDRESS="kube-master1"
HOST2_ID="master2"
HOST2_ADDRESS="kube-master2"
HOST3_ID="master3"
HOST3_ADDRESS="kube-master3"

echo ${STATE}
echo $PRIORITY
echo ${HOST1_ID}
echo $HOST1_ADDRESS

apt install net-tools
mkdir -p /etc/keepalived/
cat >/etc/keepalived/keepalived.conf <<EOF
global_defs {
    router_id LVS_DEVEL
    script_user root
    enable_script_security
    #dynamic_interfaces
}
vrrp_script check_apiserver {
    script "/etc/keepalived/check_apiserver.sh"
    interval 3
    weight -2
    fall 10
    rise 2
}
vrrp_instance VI_1 {
    state ${STATE}
    interface ${INTERFACE}
    virtual_router_id ${ROUTER_ID}
    priority ${PRIORITY}
    authentication {
        auth_type PASS
        auth_pass ${AUTH_PASS}
    }
    virtual_ipaddress {
        ${APISERVER_VIP}
    }
    track_script {
        check_apiserver
    }
}
EOF

cat >/etc/keepalived/check_apiserver.sh <<EOF
#!/bin/bash
errorExit() {
    echo "*** $*" 1>&2
    exit 1
}
curl --silent --max-time 2 --insecure https://localhost:${APISERVER_DEST_PORT}/ -o /dev/null || errorExit "Error GET https://localhost:${APISERVER_DEST_PORT}/"
if ip addr | grep -q ${APISERVER_VIP}; then
    curl --silent --max-time 2 --insecure https://${APISERVER_VIP}:${APISERVER_DEST_PORT}/ -o /dev/null || errorExit "Error GET https://${APISERVER_VIP}:${APISERVER_DEST_PORT}/"
fi
EOF
chmod 777 /etc/keepalived/check_apiserver.sh

mkdir -p /etc/kubernetes/manifests/
cat >/etc/kubernetes/manifests/keepalived.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  name: keepalived
  namespace: kube-system
spec:
  containers:
  - image: osixia/keepalived:2.0.20
    name: keepalived
    resources: {}
    securityContext:
      capabilities:
        add:
        - NET_ADMIN
        - NET_BROADCAST
        - NET_RAW
    volumeMounts:
    - mountPath: /usr/local/etc/keepalived/keepalived.conf
      name: config
    - mountPath: /etc/keepalived/check_apiserver.sh
      name: check
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/keepalived/keepalived.conf
    name: config
  - hostPath:
      path: /etc/keepalived/check_apiserver.sh
    name: check
status: {}
EOF

mkdir -p /etc/haproxy/
cat >/etc/haproxy/haproxy.cfg <<EOF
# /etc/haproxy/haproxy.cfg
#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    log 127.0.0.1 local0
    #log /dev/log local0
    #log /dev/log local1 notice
    user haproxy
    group haproxy
    daemon
#---------------------------------------------------------------------
# common defaults that all the "listen" and "backend" sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    #option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 1
    timeout http-request    10s
    timeout queue           20s
    timeout connect         5s
    timeout client          20s
    timeout server          20s
    timeout http-keep-alive 10s
    timeout check           10s
# Модуль статистики. Доступен по http://<IP адрес сервера>:9000/haproxy_stats Login:admin Pass:admin
listen stats
    bind *:9000
    mode http
    stats enable  # Enable stats page
    stats refresh 30s  # Refresh page
    stats realm Haproxy\ Statistics  # Title text for popup window
    stats uri /haproxy_stats  # Stats URI
    stats auth ...:...  # Authentication credentials
#---------------------------------------------------------------------
# apiserver frontend which proxys to the control plane nodes
#---------------------------------------------------------------------
frontend apiserver
    bind *:${APISERVER_DEST_PORT}
    mode tcp
    option tcplog
    default_backend apiserver
#---------------------------------------------------------------------
# round robin balancing for apiserver
#---------------------------------------------------------------------
backend apiserver
    option httpchk GET /healthz
    http-check expect status 200
    mode tcp
    option ssl-hello-chk
    balance     roundrobin
        server ${HOST1_ID} ${HOST1_ADDRESS}:${APISERVER_SRC_PORT} check
        server ${HOST2_ID} ${HOST2_ADDRESS}:${APISERVER_SRC_PORT} check
	server ${HOST3_ID} ${HOST3_ADDRESS}:${APISERVER_SRC_PORT} check
EOF

cat >/etc/kubernetes/manifests/haproxy.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: haproxy
  namespace: kube-system
spec:
  containers:
  - image: haproxy:2.8.0
    name: haproxy
    livenessProbe:
      failureThreshold: 8
      httpGet:
        host: localhost
        path: /healthz
        port: ${APISERVER_DEST_PORT}
        scheme: HTTPS
    volumeMounts:
    - mountPath: /usr/local/etc/haproxy/haproxy.cfg
      name: haproxyconf
      readOnly: true
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/haproxy/haproxy.cfg
      type: FileOrCreate
    name: haproxyconf
status: {}
EOF
'; done


# иницаализируем кластер
for sname in master1; do ssh root@kube-$sname "
echo ------------; hostname
kubeadm init --cri-socket=unix:///var/run/containerd/containerd.sock --pod-network-cidr=X.X.X.0/16 --control-plane-endpoint \"kube-vip1:8080\" --upload-certs --v=5 --ignore-preflight-errors=all >> init.log 2>&1
crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock ps -a
crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock logs $(crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock ps -a | grep haproxy | awk '{print $1}')
systemctl status kubelet -l
"; done


# добавляем 2 control plane ноды
for sname in master2 master3; do ssh root@kube-$sname "
echo ------------; hostname
kubeadm join --cri-socket=unix:///var/run/containerd/containerd.sock kube-vip1:8080 --token ... \
        --discovery-token-ca-cert-hash sha256:... \
        --control-plane --certificate-key ... \
        --v=5 --ignore-preflight-errors=all >> init.log 2>&1
crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock ps -a
crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock logs $(crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock ps -a | grep haproxy | awk '{print $1}')
systemctl status kubelet -l
"; done


# добавляем 3 worker ноды
for sname in worker1 worker2 worker3; do ssh root@kube-$sname "
echo ------------; hostname
kubeadm join --cri-socket=unix:///var/run/containerd/containerd.sock kube-vip1:8080 --token ... \
        --discovery-token-ca-cert-hash sha256:... \
        --v=5 --ignore-preflight-errors=all >> init.log 2>&1
crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock ps -a
systemctl status kubelet -l
"; done


# настраиваем kubectl на админской ноде
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
mkdir -p $HOME/.kube
scp kube-master1:/etc/kubernetes/admin.conf $HOME/.kube/config
chown $(id -u):$(id -g) $HOME/.kube/config
kubectl get nodes --show-labels
"; done


# добавляем метки нодам
for sname in admin1; do ssh root@kube-$sname "
k8s label nodes kube-master1 nodetype=master
k8s label nodes kube-master2 nodetype=master
k8s label nodes kube-master3 nodetype=master
k8s label nodes kube-worker1 nodetype=worker
k8s label nodes kube-worker2 nodetype=worker
k8s label nodes kube-worker3 nodetype=worker
k8s get no --show-labels
"; done


# устанавливаем calico
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
mkdir -p /etc/kubernetes/manifests/calico
wget https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/tigera-operator.yaml -P /etc/kubernetes/manifests/calico --show-progress
wget https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/custom-resources.yaml -P /etc/kubernetes/manifests/calico --show-progress
vim /etc/kubernetes/manifests/calico/custom-resources.yaml
#      #cidr: X.X.X.0/16
#      cidr: X.X.X.0/16
k8s apply -f /etc/kubernetes/manifests/calico/tigera-operator.yaml
k8s apply -f /etc/kubernetes/manifests/calico/custom-resources.yaml
k8s get all -n tigera-operator
k8s get pods -n calico-system
k8s taint nodes --all node-role.kubernetes.io/control-plane-
k8s get nodes -o wide
wget https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calicoctl.yaml -P /etc/kubernetes/manifests/calico --show-progress
k8s apply -f calicoctl.yaml
k8s exec -ti -n kube-system calicoctl -- /calicoctl get profiles
echo 'alias calicoctl="kubectl exec -i -n kube-system calicoctl -- /calicoctl"' >> ~/.bashrc
echo 'alias k8s="kubectl"' >> ~/.bashrc
su - root
calicoctl get profiles
k8s get nodes
"; done


# установим k9s
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
curl -sS https://webinstall.dev/k9s
cp k9s /usr/bin
echo 'export TERM=xterm-256color' >> ~/.bashrc
echo 'export EDITOR=vim' >> ~/.bashrc
echo 'export K9S_EDITOR=vim' >> ~/.bashrc
su - root
"; done


# !!! НЕ АКТУАЛЬНО !!! настраиваем LoadBalancer для ingress controller
for sname in worker1 worker2 worker3; do ssh root@kube-$sname '

# !!!!!!!!!! set sname if only one host s script

echo ------------; hostname
#kubeadm reset --cri-socket=unix:///var/run/containerd/containerd.sock

if [[ $sname = "worker1" ]]
then
  STATE="MASTER"
  PRIORITY="101"
else
  STATE="BACKUP"
  PRIORITY="100"
fi

INTERFACE="ens3"
ROUTER_ID="51"
AUTH_PASS="42"
APISERVER_VIP="X.X.X.228"
APISERVER_DEST_PORT="80"

echo ${sname}
echo ${STATE}
echo $PRIORITY

apt install net-tools
mkdir -p /etc/keepalived/
cat >/etc/keepalived/keepalived.conf <<EOF
global_defs {
    router_id LVS_DEVEL
    script_user root
    enable_script_security
    #dynamic_interfaces
}
vrrp_script check_apiserver {
    script "/etc/keepalived/check_apiserver.sh"
    interval 3
    weight -2
    fall 10
    rise 2
}
vrrp_instance VI_0 {
    state ${STATE}
    interface ${INTERFACE}
    virtual_router_id ${ROUTER_ID}
    priority ${PRIORITY}
    authentication {
        auth_type PASS
        auth_pass ${AUTH_PASS}
    }
    virtual_ipaddress {
        ${APISERVER_VIP}
    }
    track_script {
        check_apiserver
    }
}
EOF

cat >/etc/keepalived/check_apiserver.sh <<EOF
#!/bin/bash
errorExit() {
    echo "*** $*" 1>&2
    exit 1
}
curl --silent --max-time 2 --insecure https://localhost:${APISERVER_DEST_PORT}/ -o /dev/null || errorExit "Error GET https://localhost:${APISERVER_DEST_PORT}/"
if ip addr | grep -q ${APISERVER_VIP}; then
    curl --silent --max-time 2 --insecure https://${APISERVER_VIP}:${APISERVER_DEST_PORT}/ -o /dev/null || errorExit "Error GET https://${APISERVER_VIP}:${APISERVER_DEST_PORT}/"
fi
EOF
chmod 777 /etc/keepalived/check_apiserver.sh

mkdir -p /etc/kubernetes/manifests/
cat >/etc/kubernetes/manifests/keepalived.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  name: keepalived
  namespace: kube-system
spec:
  containers:
  - image: osixia/keepalived:2.0.20
    name: keepalived
    resources: {}
    securityContext:
      capabilities:
        add:
        - NET_ADMIN
        - NET_BROADCAST
        - NET_RAW
    volumeMounts:
    - mountPath: /usr/local/etc/keepalived/keepalived.conf
      name: config
    - mountPath: /etc/keepalived/check_apiserver.sh
      name: check
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/keepalived/keepalived.conf
    name: config
  - hostPath:
      path: /etc/keepalived/check_apiserver.sh
    name: check
status: {}
EOF
'; done


# установим DNS
for sname in admin1; do ssh root@kube-$sname '
echo ------------; hostname
apt install bind9
apt install dnsutils
echo 'zone "ruby.local" {
    type master;
    file "/etc/bind/db.ruby.local";
};' >> /etc/bind/named.conf.local
cp /etc/bind/db.local /etc/bind/db.ruby.local
vim /etc/bind/db.ruby.local
systemctl restart bind9.service
echo 'zone "X.X.X.in-addr.arpa" {
    type master;
    file "/etc/bind/db.10";
};' >> /etc/bind/named.conf.local
cp /etc/bind/db.127 /etc/bind/db.10
vim /etc/bind/db.10
systemctl restart bind9.service
echo '
kube-template1  IN      A       X.X.X.229
kube-admin1     IN      A       X.X.X.220
kube-master1    IN      A       X.X.X.221
kube-master2    IN      A       X.X.X.224
kube-master3    IN      A       X.X.X.223
kube-worker1    IN      A       X.X.X.225
kube-worker2    IN      A       X.X.X.226
kube-worker3    IN      A       X.X.X.227
kube-vip1       IN      A       X.X.X.222
' >> /etc/bind/db.ruby.local
systemctl restart bind9.service

# on WINDOWS workstation set DNS-client
netsh interface show interface
netsh interface ipv4 add dnsserver "Ethernet 2" address=X.X.X.220 index=1
netsh interface show interface
ping gitlab.ruby.local
'; done


# скопируем настройки DNS клиента на все сервера кластера
for sname in master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "
echo ------------; hostname
echo 'nameserver X.X.X.220' >> /etc/resolv.conf
cat /etc/resolv.conf
"; done


#настраиваем ingress-controller
for sname in admin1; do ssh root@kube-$sname '
echo ------------; hostname
mkdir -p /etc/kubernetes/manifests/metallb

k8s get configmap kube-proxy -n kube-system -o yaml | sed -e "s/strictARP: false/strictARP: true/" | sed -e "s/mode: \"\"/mode: \"ipvs\"/" | kubectl diff -f - -n kube-system
k8s get configmap kube-proxy -n kube-system -o yaml | sed -e "s/strictARP: false/strictARP: true/" | sed -e "s/mode: \"\"/mode: \"ipvs\"/" | kubectl apply -f - -n kube-system
k8s get configmap kube-proxy -n kube-system -o yaml | sed -e "s/strictARP: false/strictARP: true/" | sed -e "s/mode: \"\"/mode: \"ipvs\"/" | kubectl diff -f - -n kube-system
wget https://raw.githubusercontent.com/metallb/metallb/v0.13.10/config/manifests/metallb-native.yaml -P /etc/kubernetes/manifests/metallb --show-progress
k8s apply -f /etc/kubernetes/manifests/metallb/metallb-native.yaml

wget https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.0/deploy/static/provider/baremetal/deploy.yaml -P /etc/kubernetes/manifests/metallb --show-progress
mv /etc/kubernetes/manifests/metallb/deploy.yaml /etc/kubernetes/manifests/metallb/ingress-nginx-deploy.yaml
vim /etc/kubernetes/manifests/metallb/ingress-nginx-deploy.yaml
#kind: Service
#spec:
#  #externalIPs:
#  #- X.X.X.222
#  #type: NodePort
#  type: LoadBalancer
k8s apply -f /etc/kubernetes/manifests/metallb/ingress-nginx-deploy.yaml
k8s delete -A ValidatingWebhookConfiguration ingress-nginx-admission
k8s get pods -n ingress-nginx --show-labels
k8s wait -n ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=120s
POD_NAMESPACE=ingress-nginx
POD_NAME=$(kubectl get pods -n $POD_NAMESPACE -l app.kubernetes.io/name=ingress-nginx --field-selector=status.phase=Running -o name)
k8s exec $POD_NAME -n $POD_NAMESPACE -- /nginx-ingress-controller --version

cat >/etc/kubernetes/manifests/metallb/ipaddress_pools.yaml <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: production
  namespace: metallb-system
spec:
  addresses:
  - X.X.X.228-X.X.X.228
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: l2-advert
  namespace: metallb-system
EOF
k8s apply -f /etc/kubernetes/manifests/metallb/ipaddress_pools.yaml
'; done


# установим Dashboard для Kubernetes-а
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
mkdir -p /etc/kubernetes/manifests/dashboard
wget https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml -P /etc/kubernetes/manifests/dashboard
k8s apply -f /etc/kubernetes/manifests/dashboard/recommended.yaml
#namespace/kubernetes-dashboard created
#serviceaccount/kubernetes-dashboard created
#service/kubernetes-dashboard created
#secret/kubernetes-dashboard-certs created
#secret/kubernetes-dashboard-csrf created
#secret/kubernetes-dashboard-key-holder created
#configmap/kubernetes-dashboard-settings created
#role.rbac.authorization.k8s.io/kubernetes-dashboard created
#clusterrole.rbac.authorization.k8s.io/kubernetes-dashboard created
#rolebinding.rbac.authorization.k8s.io/kubernetes-dashboard created
#clusterrolebinding.rbac.authorization.k8s.io/kubernetes-dashboard created
#deployment.apps/kubernetes-dashboard created
#service/dashboard-metrics-scraper created
#deployment.apps/dashboard-metrics-scraper created

apt install xdg-utils firefox selinux-utils
cat >/etc/kubernetes/manifests/dashboard/dashboard-ServiceAccount.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard
EOF

cat >/etc/kubernetes/manifests/dashboard/dashboard-ClusterRoleBinding.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard

cat >/etc/kubernetes/manifests/dashboard/dashboard-ClusterRoleBinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kubernetes-dashboard
EOF

k8s apply -f /etc/kubernetes/manifests/dashboard/dashboard-ClusterRoleBinding.yaml
k8s apply -f /etc/kubernetes/manifests/dashboard/dashboard-ServiceAccount.yaml
k8s -n kubernetes-dashboard create token admin-user

vim /etc/kubernetes/manifests/dashboard/dashboard_ingress_http.yaml
k8s apply -f /etc/kubernetes/manifests/dashboard/dashboard_ingress_http.yaml
#echo 'X.X.X.228 dashboard.ruby.local' >> /etc/hosts
echo 'dashboard       IN      A       X.X.X.228' >> /etc/bind/db.ruby.local
systemctl restart bind9.service
curl https://dashboard.ruby.local
#scp ~/.kube/config to windows client and apply on web interface while login

#k8s proxy --address='X.X.X.220' --accept-hosts='^localhost$,^127.0.0.1$,^10.1.255.73$,^192.168.0.11$,^[::1]$' --disable-filter=true --port=8011
#k8s proxy --address='X.X.X.220' --disable-filter=true --port=8011
#k8s port-forward svc/kubernetes-dashboard 8443:443 -n kubernetes-dashboard --address=X.X.X.220
#k8s proxy --address='X.X.X.220' --port=8001 --accept-hosts='^*$'
curl X.X.X.220:8001/api/v1/namespaces
curl http://X.X.X.220:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/

vim /etc/kubernetes/manifests/dashboard/admin-user.yaml
k8s apply -f /etc/kubernetes/manifests/dashboard/admin-user.yaml
kubectl create token admin-user -n kubernetes-dashboard

# on windows workstation set DNS-client
netsh interface show interface
netsh interface ipv4 add dnsserver "Ethernet 2" address=X.X.X.220 index=1
ping dashboard.ruby.local

"; done


# устанавливаем EFK
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
mkdir -p /etc/kubernetes/manifests/efk
vim /etc/kubernetes/manifests/efk/elasticsearch_ns.yaml
vim /etc/kubernetes/manifests/efk/elasticsearch_pv.yaml
vim /etc/kubernetes/manifests/efk/elasticsearch_svc.yaml
vim /etc/kubernetes/manifests/efk/elasticsearch_ss.yaml
k8s create -f /etc/kubernetes/manifests/efk/elasticsearch_ns.yaml
k8s create -f /etc/kubernetes/manifests/efk/elasticsearch_pv.yaml
k8s create -f /etc/kubernetes/manifests/efk/elasticsearch_svc.yaml
k8s create -f /etc/kubernetes/manifests/efk/elasticsearch_ss.yaml
vim /etc/kubernetes/manifests/efk/kibana.yaml
vim /etc/kubernetes/manifests/efk/fluentd.yaml
k8s create -f /etc/kubernetes/manifests/efk/kibana.yaml
k8s create -f /etc/kubernetes/manifests/efk/fluentd.yaml
vim /etc/kubernetes/manifests/efk/kibana_ingress.yaml
k8s apply -f /etc/kubernetes/manifests/efk/kibana_ingress.yaml
#echo 'X.X.X.228 elastic.ruby.local' >> /etc/hosts
#echo 'X.X.X.228 kibana.ruby.local' >> /etc/hosts
echo 'elastic       IN      A       X.X.X.228' >> /etc/bind/db.ruby.local
echo 'kibana       IN      A       X.X.X.228' >> /etc/bind/db.ruby.local
systemctl restart bind9.service
curl elastic.ruby.local/_cluster/state?pretty
curl kibana.ruby.local
#k8s port-forward es-cluster-0 9200:9200 --namespace=kube-logging --address=X.X.X.220
#curl http://localhost:9200/_cluster/state?pretty
#k8s port-forward kibana-74d6d66597-c25lk 5601:5601 --namespace=kube-logging --address=X.X.X.220
#url http://X.X.X.220:5601
k8s exec -n kube-logging --stdin --tty $(k8s get pods -n kube-logging | grep kibana | grep Running | awk '{print $1}') -- /usr/share/kibana/bin/kibana-verification-code	

# настраиваем визуализацию, enable 'Include hidden indices', добавляем индексы
curl http://kibana.ruby.local/app/management/data/index_management/indices?includeHiddenIndices=true
# верхний левый список позваляет добавлять новые визуализации, в т.ч. и тестовые
curl http://kibana.ruby.local/app/discover#/
# Create data view -> Allow hidden and system indices -> Index pattern & Name
"; done


# установим мониторинг Helm + Prometheus + Grafana
for sname in admin1; do ssh root@kube-$sname '
echo ------------; hostname
mkdir -p /etc/kubernetes/manifests/prometheus
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
helm version

k8s create ns monitoring
vim /etc/kubernetes/manifests/prometheus/prometheus_pv.yaml
k8s apply -f /etc/kubernetes/manifests/prometheus/prometheus_pv.yaml
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm show values prometheus-community/prometheus > /etc/kubernetes/manifests/prometheus/values.prometheus.yaml
vim /etc/kubernetes/manifests/prometheus/values.prometheus.yaml
#  securityContext:
#    runAsUser: 0
#    runAsNonRoot: false
#    runAsGroup: 0
#    fsGroup: 0
helm upgrade --install my-prom prometheus-community/prometheus -n monitoring -f /etc/kubernetes/manifests/prometheus/values.prometheus.yaml
k8s get pods -n monitoring
k8s get pods -l "app.kubernetes.io/instance=my-prom" -n monitoring

helm install prometheus-postgres-exporter prometheus-community/prometheus-postgres-exporter -n monitoring
vim /etc/kubernetes/manifests/prometheus/prometheus_ingress.yaml
vim /etc/kubernetes/manifests/prometheus/prometheus_exporter_ingress.yaml
k8s apply -f /etc/kubernetes/manifests/prometheus/prometheus_ingress.yaml
#echo "X.X.X.228 grafana.ruby.local
#X.X.X.228 prometheus.ruby.local
#X.X.X.228 promalert.ruby.local" >> /etc/hosts
echo "grafana       IN      A       X.X.X.228" >> /etc/bind/db.ruby.local
echo "prometheus       IN      A       X.X.X.228" >> /etc/bind/db.ruby.local
echo "prometheus-exporter       IN      A       X.X.X.228" >> /etc/bind/db.ruby.local
echo "promalert       IN      A       X.X.X.228" >> /etc/bind/db.ruby.local
systemctl restart bind9.service

curl grafana.ruby.local
curl prometheus.ruby.local
curl prometheus-exporter.local
curl promalert.ruby.local

#Get the Prometheus server URL by running these commands in the same shell:
k8s port-forward $(kubectl get pods --namespace monitoring -l "app.kubernetes.io/name=prometheus,app.kubernetes.io/instance=my-prom" -o jsonpath="{.items[0].metadata.name}") 9090 -n monitoring --address=X.X.X.220
#Get the Alertmanager URL by running these commands in the same shell:
k8s port-forward $(kubectl get pods --namespace monitoring -l "app.kubernetes.io/name=alertmanager,app.kubernetes.io/instance=my-prom" -o jsonpath="{.items[0].metadata.name}") 9093 -n monitoring --address=X.X.X.220
#Get the PushGateway URL by running these commands in the same shell:
export POD_NAME=$(kubectl get pods --namespace monitoring -l "app=prometheus-pushgateway,component=pushgateway" -o jsonpath="{.items[0].metadata.name}")
k8s --namespace monitoring port-forward $POD_NAME 9091

helm repo add tricksterproxy https://helm.tricksterproxy.io
helm repo update
vim /etc/kubernetes/manifests/prometheus/trickster.yaml
helm install trickster tricksterproxy/trickster --namespace monitoring -f /etc/kubernetes/manifests/prometheus/trickster.yaml
k8s get pods -l "app=trickster" -n monitoring
#kubectl port-forward $(kubectl get pods --namespace monitoring -l "app=trickster,component=trickster" -o jsonpath="{.items[0].metadata.name}") 9090 -n monitoring --address=X.X.X.220

vim /etc/kubernetes/manifests/prometheus/grafana_pv.yaml
vim /etc/kubernetes/manifests/prometheus/grafana.yaml
k8s apply -f /etc/kubernetes/manifests/prometheus/grafana_pv.yaml -n monitoring
k8s apply -f /etc/kubernetes/manifests/prometheus/grafana.yaml -n monitoring
kubectl get pods -l "app=grafana" -n monitoring
export GRAFANA_IP=$(kubectl get service/grafana -o jsonpath='{.status.loadBalancer.ingress[0].ip}' -n monitioring) && \
export GRAFANA_PORT=$(kubectl get service/grafana -o jsonpath='{.spec.ports[0].port}' -n monitoring) && \
echo http://$GRAFANA_IP:$GRAFANA_PORT

# настроим визуализацию grafana, создадим ресурсы
# http://elasticsearch.kube-logging.svc.cluster.local:9200 и http://my-prom-prometheus-server.monitoring.svc.cluster.local:80
http://grafana.ruby.local/connections/datasources
# создадим дашборды not "New" -> "Import"
curl http://grafana.ruby.local/dashboard/import
# json-файлы можно взять из и складировать в папке grafana_json:
curl https://grafana.com/grafana/dashboards/
mkdir -p /etc/kubernetes/manifests/prometheus/grafana_json
http://grafana.ruby.local/dashboards
'; done


# установим GitLab, Gitlab Runner и Buildah
for sname in admin1; do ssh root@kube-$sname '
echo ------------; hostname
echo "gitlab          IN      A       X.X.X.220" >> /etc/bind/db.ruby.local
systemctl restart bind9.service
apt-get update
apt-get install curl openssh-server ca-certificates tzdata perl
apt-get install postfix
#Internet Site
#kube-admin1
ln -s /data/gitlab /var/opt/gitlab
wget https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh -P /etc/kubernetes/manifests
mv /etc/kubernetes/manifests/script.deb.sh /etc/kubernetes/manifests/gitlab.install.deb.sh
curl https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | sudo bash
EXTERNAL_URL="https://gitlab.ruby.local" apt-get install gitlab-ce | tee -a gitlab-install.log

vim /etc/gitlab/gitlab.rb
# git_data_dirs({
#   "default" => {
#     "path" => "/data/git-data"
#    }
# })
#registry_external_url 'https://gitlab.ruby.local'
#### Settings used by Registry application
#registry['enable'] = true
#registry['username'] = "..."
#registry['password'] = "..."
#registry['group'] = "..."
#registry['uid'] = nil
#registry['gid'] = nil
#registry['dir'] = "/var/opt/gitlab/registry"
#registry['registry_http_addr'] = "X.X.X.220:5000"
gitlab-ctl reconfigure
gitlab-ctl restart
systemctl status gitlab-runsvdir.service
gitlab-ctl status

curl https://gitlab.ruby.local
curl https://gitlab.ruby.local:5000 # gitlab container registry
cat /etc/gitlab/initial_root_password
#Password:
#Deploy tokens - all rights
curl https://gitlab.ruby.local/xwiki_users/xwiki/-/settings/repository
#set CI/CD Settings -> Variables
curl https://gitlab.ruby.local/xwiki_users/xwiki/-/settings/ci_cd
#CI_DEPLOY_USER=...
#CI_DEPLOY_PASSWORD=...
buildah login -v --tls-verify=false -u registry gitlab.ruby.local:5000
#Password: ...
#Used:  /run/user/0/containers/auth.json
#Login Succeeded!

#add group xwiki-users
https://gitlab.ruby.local/dashboard/groups
#add project
https://gitlab.ruby.local/dashboard/projects
#add ssh key
https://gitlab.ruby.local/-/profile/keys/
#add ssh key on client machine
ssh-keygen -t ed25519 -C gitlab.ruby.local
cat C:\Users\busyg/.ssh/id_ed25519.pub
#ssh-ed25519 ... gitlab.ruby.local
cat /root/.ssh/id_ed25519.pub
ssh-ed25519 ... root@kube-admin1

#install gitlab-runners
#create and register runner
https://gitlab.ruby.local/xwiki_users/xwiki/-/runners
#gitlab-runner register  --url https://gitlab.ruby.local  --token ...
#gitlab-runner run

curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
sudo apt-get install gitlab-runner
cd ~
openssl rand -writerand .rnd
chmod a+rwx ~/.rnd
cd /tmp
mkdir essai
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=Acme Root CA" -out ca.crt
openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=*gitlab.ruby.local" -out server.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:gitlab.ruby.local") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
cd /etc/gitlab/
mkdir bck-ssl
cd ssl
mv gitlab.ruby.local* ../bck-ssl/
mv X.X.X.220.* ../bck-ssl/
mv /tmp/ca.* .
mv /tmp/server.* .
mv server.crt gitlab.ruby.local.crt
mv server.key gitlab.ruby.local.key
mv server.csr ../bck-ssl/
gitlab-ctl reconfigure
gitlab-ctl restart
cd ~/.ssh
ssh-keygen -t rsa
chmod 600 id_rsa
chmod 644 id_rsa.pub
cd /etc/gitlab/ssl
cp ca.crt ca.pem
cp ca.pem /etc/ssl/certs/ca.pem
#!!! copy /etc/gitlab/ssl/ca.crt to local machine and apply certificate
cd /etc/ssl/certs/
update-ca-certificates
gitlab-ctl restart
gitlab-runner register --tls-ca-file=/etc/gitlab/ssl/ca.crt --url https://gitlab.ruby.local --registration-token ...
#https://gitlab.ruby.local
#...
#kube-admin1
#docker
#ruby:2.7
cat /etc/gitlab-runner/config.toml

#helm repo add gitlab https://charts.gitlab.io
#helm pull gitlab/gitlab-runner
#unzip /root/scripts/gitlab-runner
#echo "gitlabUrl: https://gitlab.ruby.local/" >> /root/scripts/gitlab-runner/values.yaml
#k8s create ns gitlab-runner
#helm delete --namespace gitlab-runner gitlab-runner
#helm upgrade --install --namespace gitlab-runner gitlab-runner --set gitlabUrl=https://X.X.X.220/,runnerRegistrationToken='...' /root/scripts/gitlab-runner
#helm upgrade --install --namespace gitlab-runner gitlab-runner --set gitlabUrl=https://gitlab.ruby.local/,runnerRegistrationToken='...'/root/scripts/gitlab-runner
#k8s cp /etc/gitlab/ssl/*.crt <pod>:/etc/gitlab-runner/certs/
#k8s get pod -n gitlab-runner | grep gitlab-runner | awk '{print $1;}' | sed 's/^/k8s cp \/etc\/gitlab\/ssl\/*.crt /' | sed 's/$/:\/etc\/gitlab-runner\/certs\//'

apt install buildah
'; done


# установим docker
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
apt update
apt install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt update
apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
echo '{
  "dns": ["8.8.8.8", "8.8.4.4"]
}' > /etc/docker/daemon.json
systemctl restart docker
systemctl status docker
systemctl disable kubelet
systemctl stop kubelet
systemctl status kubelet

#создадим image
docker login
username: ...
password: ...
# create repository xcron
curl https://hub.docker.com/repository/docker/busygina83/xcron/general
#!!! change version "v1" !!!
docker build --network host -t busygina83/xcron:v1 -f Dockerfile.cron .
docker image list
docker push busygina83/xcron:v1
curl https://hub.docker.com/repository/docker/busygina83/xcron/general
#docker pull busygina83/xcron:v1
"; done


# установим приложение XWiki
for sname in admin1; do ssh root@kube-$sname '
echo ------------; hostname
k8s create ns xwiki
mkdir -p /etc/kubernetes/manifests/xwiki
vim /etc/kubernetes/manifests/xwiki/0_xwiki_pv.yaml
k8s apply -f /etc/kubernetes/manifests/xwiki/0_xwiki_pv.yaml
# postgres/tooruser or tooradmin
vim /etc/kubernetes/manifests/xwiki/1_xpostgres.yaml
k8s apply -f /etc/kubernetes/manifests/xwiki/1_xpostgres.yaml
#pg_dumpall -> psql import dump-file

vim /nfs/cluster/xwiki/data/hibernate.cfg.xml
#<property name="connection.url">jdbc:postgresql://X.X.X.X:5432/wikidb</property>
vim /etc/kubernetes/manifests/xwiki/2_xwiki.yaml
k8s apply -f /etc/kubernetes/manifests/xwiki/2_xwiki.yaml
#restore data from backup

vim /etc/kubernetes/manifests/xwiki/3_xpgadmin.yaml
k8s apply -f /etc/kubernetes/manifests/xwiki/3_xpgadmin.yaml
#connect to database X.X.X.X@postgres:tooradmin

vim /etc/kubernetes/manifests/xwiki/Dockerfile.cron
vim /etc/kubernetes/manifests/xwiki/cron_restore.sh
vim /etc/kubernetes/manifests/xwiki/cron_start.sh #change IP "pgsip"
chmod 777 /etc/kubernetes/manifests/xwiki/cron_restore.sh
chmod 777 /etc/kubernetes/manifests/xwiki/cron_start.sh
buildah login -v --tls-verify=false -u registry localhost:5000
#Password:
#Used:  /run/user/0/containers/auth.json
#Login Succeeded!
cd /etc/kubernetes/manifests/xwiki/
buildah build -t xcron:v1 -f Dockerfile.cron .
#buildah build -t xcron:v1 -f /etc/kubernetes/manifests/xwiki/Dockerfile.cron /etc/kubernetes/manifests/xwiki/
buildah images
buildah images | grep xcron | grep v1 | awk '{print $3}'

vim /etc/kubernetes/manifests/xwiki/4_xcron.yaml
k8s apply -f /etc/kubernetes/manifests/xwiki/4_xcron.yaml

echo "xwiki            IN      A       X.X.X.228" >> /etc/bind/db.ruby.local
echo "pgadmin          IN      A       X.X.X.228" >> /etc/bind/db.ruby.local
systemctl restart bind9.service

'; done


# CI/CD settings
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
cd /etc/kubernetes
git init
#echo 'nameserver X.X.X.220' >> /etc/resolv.conf
git remote add origin https://gitlab.ruby.local/xwiki_users/xwiki.git
Username for 'https://gitlab.ruby.local':
Password for 'https://root@gitlab.ruby.local':
git branch -M main
git config --global credential.helper store
git branch --set-upstream-to=origin/main main
git config pull.rebase true
git pull origin main
git status
git add .
git config --global user.email 
git config --global user.name 
git commit -m v0
git push -uf origin main
"; done



for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
"; done

