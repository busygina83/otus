Описание выполненных работ, а также их автоматизация в виде скриптов, изложена в install_otus.sh. Во вложенных папках дополнительные файлы, участвующие в установке.

Настроены 7 ВМ с ОС UBUNTU (3 control-plane + 3 worker-node + 1 admin-node).
Настроены по 2 интерфейса: для интерконекта и подключения из вне, с возможностью безпарольного свзи нод по интерконнекту.
Установлены необходимые системные утилиты, настроен локальный DNS (/etc/hosts).
Установлены container runtime, kubeadm, kubelet, kubectl, containerd, crio, cri-dockerd.
Настроен CNI, установлен Calico.
Настроен Load Balancer для control-plain.
Инициализирован кластер.
Настроены утилиты kubectl (k8s), k9s, calicoctl/
Установлен Dashboard и EFK.

