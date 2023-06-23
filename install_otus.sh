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
	ssh-ed25519 AAAA... root@kube-template1
	ssh-ed25519 AAAA... root@kube-admin1
	ssh-ed25519 AAAA... root@kube-master1
	ssh-ed25519 AAAA... root@kube-master2
	ssh-ed25519 AAAA... root@kube-master3
	ssh-ed25519 AAAA... root@kube-worker1
	ssh-ed25519 AAAA... root@kube-worker2
	ssh-ed25519 AAAA... root@kube-worker3

for sname in template1 admin1 master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "echo ------------; hostname; cat /etc/hosts | grep template; sed -i 's/template/template1/' /etc/hosts; cat /etc/hosts | grep template"; done


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
for sname in template1 admin1 master1 master2 master3 worker1 worker2 worker3
do
ssh root@kube-$sname '
apt update
apt list --upgradable
apt upgrade
apt install inetutils-traceroute ntpdate ntp mc
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
            "subnet": "10.88.0.0/16"
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
for sname in master1 master2 master3; do ssh root@kube-$sname "

# !!!!!!!!!! set sname if only one host's script

echo ------------; hostname
kubeadm reset --cri-socket=unix:///var/run/containerd/containerd.sock

if [[ $sname = 'master1' ]]
then
  STATE='MASTER'
  PRIORITY='101'
else
  STATE='BACKUP'
  PRIORITY='100'
fi

INTERFACE='ens4'
ROUTER_ID='51'
AUTH_PASS='42'
APISERVER_VIP='X.X.X.222'
#APISERVER_VIP='kube-vip1'
APISERVER_DEST_PORT='8080'
APISERVER_SRC_PORT='6443'
HOST1_ID='master1'
HOST1_ADDRESS='kube-master1'
HOST2_ID='master2'
HOST2_ADDRESS='kube-master2'
HOST3_ID='master3'
HOST3_ADDRESS='kube-master3'

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
    script \"/etc/keepalived/check_apiserver.sh\"
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
# common defaults that all the 'listen' and 'backend' sections will
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
    stats auth admin:admin  # Authentication credentials
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
"; done


# иницаализируем кластер
for sname in master1; do ssh root@kube-$sname "
echo ------------; hostname
kubeadm init --cri-socket=unix:///var/run/containerd/containerd.sock --pod-network-cidr=10.88.0.0/16 --control-plane-endpoint "kube-vip1:8080" --upload-certs --v=5 --ignore-preflight-errors=all >> init.log 2>&1
crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock ps -a
crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock logs $(crictl --runtime-endpoint unix:///var/run/containerd/containerd.sock ps -a | grep haproxy | awk '{print $1}')
systemctl status kubelet -l
"; done


# добавляем 2 control plane ноды
for sname in master2 master3; do ssh root@kube-$sname "
echo ------------; hostname
kubeadm join --cri-socket=unix:///var/run/containerd/containerd.sock kube-vip1:8080 --token ... \
        --discovery-token-ca-cert-hash ... \
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
        --discovery-token-ca-cert-hash ... \
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


# устанавливаем calico
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/tigera-operator.yaml
kubectl get all -n tigera-operator
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/custom-resources.yaml
kubectl get pods -n calico-system
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
kubectl get nodes -o wide
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calicoctl.yaml
kubectl exec -ti -n kube-system calicoctl -- /calicoctl get profiles
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


# установим Dashboard для Kubernetes-а
for sname in admin1; do ssh root@kube-$sname "
echo ------------; hostname
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml
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
cat >/etc/kubernetes/manifests/dashboard-ServiceAccount.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard
EOF

cat >/etc/kubernetes/manifests/dashboard-ClusterRoleBinding.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard
root@kube-admin1:/etc/kubernetes/manifests# cat dashboard-ClusterRoleBinding.yaml
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

k8s apply -f /etc/kubernetes/manifests/dashboard-ClusterRoleBinding.yaml
k8s apply -f /etc/kubernetes/manifests/dashboard-ServiceAccount.yaml
kubectl -n kubernetes-dashboard create token admin-user
...
#kubectl proxy --address='X.X.X.220' --accept-hosts='^localhost$,^127.0.0.1$,^10.1.255.73$,^192.168.0.11$,^[::1]$' --disable-filter=true --port=8011
#kubectl proxy --address='X.X.X.220' --disable-filter=true --port=8011
kubectl proxy --address='X.X.X.220' --port=8001 --accept-hosts='^*$'
curl X.X.X.220:8001/api/v1/namespaces
curl http://X.X.X.220:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/
"; done


# устанавливаем EFK
for sname in admin1; do ssh root@kube-$sname "
vim /etc/kubernetes/manifests/elasticsearch_ns.yaml
vim /etc/kubernetes/manifests/elasticsearch_pv.yaml
vim /etc/kubernetes/manifests/elasticsearch_svc.yaml
vim /etc/kubernetes/manifests/elasticsearch_ss.yaml
k8s create -f /etc/kubernetes/manifests/elasticsearch_ns.yaml
k8s create -f /etc/kubernetes/manifests/elasticsearch_pv.yaml
k8s create -f /etc/kubernetes/manifests/elasticsearch_svc.yaml
k8s create -f /etc/kubernetes/manifests/elasticsearch_ss.yaml
vim /etc/kubernetes/manifests/kibana.yaml
vim /etc/kubernetes/manifests/fluentd.yaml
k8s create -f /etc/kubernetes/manifests/kibana.yaml
k8s create -f /etc/kubernetes/manifests/fluentd.yaml
kubectl port-forward es-cluster-0 9200:9200 --namespace=kube-logging --address=X.X.X.220
curl http://localhost:9200/_cluster/state?pretty
kubectl port-forward kibana-74d6d66597-c25lk 5601:5601 --namespace=kube-logging --address=X.X.X.220
url http://X.X.X.220:5601
k8s exec -n kube-logging --stdin --tty $(k8s get pods -n kube-logging | grep kibana | grep Running | awk '{print $1}') -- /usr/share/kibana/bin/kibana-verification-code	
"; done


for sname in master1 master2 master3 worker1 worker2 worker3; do ssh root@kube-$sname "
echo ------------; hostname
"; done

