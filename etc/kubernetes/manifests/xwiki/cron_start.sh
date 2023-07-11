#!/bin/bash
#----------------------------------------------------------------------------------------------
#параметры ОБЯЗАТЕЛЬНЫЕ для ручного заполнения
# Внешний IP адрес данного сервера, на который проброшен порт 5432 постргресса из контейнера
pgsip=X.X.X.X
# Количество дней хранения ежедневных бэкапов постргеса и логов бэкапа
pgsday=31
#-----------------------------------------------------------------------------------------------

#проверяем статус crontab и при необходимости запускаем его
croncmd=cron
cronstat=`service $croncmd status`
if [[ $cronstat =~ " is running" ]]; then
	echo "сервис $croncmd уже запущен"
else
	echo "сервис $croncmd еще не запущен"
	service $croncmd start
	cronstat=`service $croncmd status`

	if [[ $cronstat =~ " is running" ]]; then
                echo "сервис $croncmd запущен"
        else
                echo "возникла ошибка при запуске сервиса $croncmd, проверьте статус командой:"
                echo "service $croncmd status"
        fi
fi

#если crontab успешно запущен - настраиваем бэкап postgres по расписанию
sleep 2
cronstat=`service $croncmd status`
echo "Итоговый статус $croncmd $cronstat"
if [[ $cronstat =~ " is running" ]]; then
	#создаем директорию под бэкапы, если её еще нет
        if [[ ! -d /var/lib/postgresql/backup/$pgsip ]]; then
                mkdir /var/lib/postgresql/backup/$pgsip
                touch /var/lib/postgresql/backup/$pgsip/pg_basebackup.log
                chmod -R 7777 /var/lib/postgresql/backup/$pgsip
        fi
	
	echo "/var/lib/postgresql/backup/$pgsip/pg_basebackup.log {" > /etc/logrotate.d/pg_basebackup
        echo "su root root" >> /etc/logrotate.d/pg_basebackup
        echo "daily" >> /etc/logrotate.d/pg_basebackup
        echo "rotate $pgsday" >> /etc/logrotate.d/pg_basebackup
        echo "create" >> /etc/logrotate.d/pg_basebackup
        echo "}" >> /etc/logrotate.d/pg_basebackup
        logrotate -dv /etc/logrotate.d/pg_basebackup
        echo "/etc/logrotate.d/pg_basebackup:"
        echo `cat /etc/logrotate.d/pg_basebackup`

        echo "for x in \`ls -l | egrep '[[:digit:]]{4}\-[[:digit:]]{2}\-[[:digit:]]{2}\_[[:digit:]]{2}\-[[:digit:]]{2}\-[[:digit:]]{2}' | awk '{print \$9}'\`; do xx=\`cut -c 1-10 <<< \$x\`; pgsdate=\$(date -I -d '- $pgsday day'); if [[ \$xx < \$pgsdate ]]; then echo \"Delete backup /var/lib/postgresql/backup/$pgsip/\$x\"; rm -r /var/lib/postgresql/backup/$pgsip/\$x; fi; done;" > /home/pg_rmbackup.sh
        chmod 0000 /home/pg_rmbackup.sh
        echo "/home/pg_rmbackup.sh:"
        echo `cat /home/pg_rmbackup.sh`

        crontab -l | { cat; echo "# Полный ежедневный бэкап Postgres БД и атачментов, содержащий информацию о документах портала Xwiki"; } | crontab -
        crontab -l | { cat; echo "0 1 * * * dpath=\$(date +\\%Y-\\%m-\\%d_\\%H-\\%M-\\%S) && cd ~postgres && su postgres -c 'dpath=\$(date +\\%Y-\\%m-\\%d_\\%H-\\%M-\\%S) && /bin/echo \$dpath >> /var/lib/postgresql/backup/$pgsip/pg_basebackup.log && /usr/bin/pg_basebackup -h $pgsip -p 5432 --no-password -Ft -z -P -D /var/lib/postgresql/backup/$pgsip/\$dpath >> /var/lib/postgresql/backup/$pgsip/pg_basebackup.log 2>&1' && cd /usr/local/xwiki/data && /usr/bin/tar -czvf /var/lib/postgresql/backup/$pgsip/\$dpath/xwiki_store.tar.gz store 2>&1 >> /var/lib/postgresql/backup/$pgsip/pg_basebackup.log && /usr/bin/tar -czvf /var/lib/postgresql/backup/$pgsip/\$dpath/xwiki_extension.tar.gz extension 2>&1 >> /var/lib/postgresql/backup/$pgsip/pg_basebackup.log"; } | crontab -
        crontab -l | { cat; echo "# Ежедневный ротейт лога бэкапов, с одновременным удалением ротейт-логов старше $pgsday дней"; } | crontab -
        crontab -l | { cat; echo "#0 1 * * * dpath=\$(date +\\%Y-\\%m-\\%d_\\%H-\\%M-\\%S) && /bin/echo \$dpath >> /var/lib/postgresql/backup/$pgsip/pg_logrotate.log && /usr/sbin/logrotate -fv /etc/logrotate.d/pg_basebackup >> /var/lib/postgresql/backup/$pgsip/pg_logrotate.log 2>&1"; } | crontab -
        crontab -l | { cat; echo "# Ежедневное удаление бэкапов, старше $pgsday дней"; } | crontab -
        crontab -l | { cat; echo "0 1 * * * dpath=\$(date +\\%Y-\\%m-\\%d_\\%H-\\%M-\\%S) && /bin/echo \$dpath >> /var/lib/postgresql/backup/$pgsip/pg_rmbackup.log && cd /var/lib/postgresql/backup/$pgsip &&/bin/bash /home/pg_rmbackup.sh >> /var/lib/postgresql/backup/$pgsip/pg_rmbackup.log 2>&1"; } | crontab -
        crontab -l
fi

