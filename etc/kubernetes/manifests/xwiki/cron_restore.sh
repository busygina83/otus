#!/bin/bash
if ! [ -z "$1" ]; then
	fromip=$1
	isrec=0
	if [[ -d ../backup/$fromip ]]; then
		if [[ -f ../backup/$fromip/pg_basebackup.log ]]; then
			if ! [ -z "$2" ]; then
				pgsdate=$2
			else
				#pgsdate=`egrep '[[:digit:]]{4}\-[[:digit:]]{2}\-[[:digit:]]{2}\_[[:digit:]]{2}\-[[:digit:]]{2}\-[[:digit:]]{2}' ../backup/$fromip/pg_basebackup.log* | tail -1`
				pgsdate=`egrep '[[:digit:]]{4}\-[[:digit:]]{2}\-[[:digit:]]{2}\_[[:digit:]]{2}\-[[:digit:]]{2}\-[[:digit:]]{2}' ../backup/$fromip/pg_basebackup.log* | cut -d ":" -f2 | sort | tail -1`
			echo "Дата бэкапа для восстановления $pgsdate"
			fi
			if [[ -d ../backup/$fromip/$pgsdate ]]; then
				if [[ -f ../backup/$fromip/$pgsdate/backup_manifest && -f ../backup/$fromip/$pgsdate/base.tar.gz && -f ../backup/$fromip/$pgsdate/pg_wal.tar.gz && -f ../backup/$fromip/$pgsdate/xwiki_store.tar.gz && -f ../backup/$fromip/$pgsdate/xwiki_extension.tar.gz ]]; then
					pgsip=`egrep '^pgsip=' ./cron//cron_start.sh | head -1 | tr -d pgsip=`
					#создаем директорию под бэкапы, если её еще нет
                                        if [[ ! -d ../backup/$pgsip ]]; then
                                                mkdir ../backup/$pgsip/pg_basetargz
                                                touch ../backup/$pgsip/pg_basetargz.log
                                                chmod -R 7777 ../backup/$pgsip
                                                echo "Директорию ../backup/$pgsip/pg_basetargz для архивов создали"
                                        else
                                                echo "Уже есть директория ../backup/$pgsip/pg_basetargz для архивов"
                                        fi
					#если контейнер с постгресом запущен, останавливаем все контейнеры подсистемы xwiki
					if [ "$( docker container inspect -f '{{.State.Running}}' postgres_container )" == "true" ]; then
						sh ./xwiki_stop.sh
						echo "Остановили контейнеры подсистемы xwiki"
					else
						echo "Контейнер с постгресом postgres_container уже остановлен"
					fi
					#архивируем существующую БД постгреса
					tardate=$(date "+%Y-%m-%d_%H-%M-%S")
					if [[ -d ./postgres/data/pgdata ]]; then
						if [ "$(ls -A ./postgres/data/pgdata)" ]; then
							/bin/echo $tardate >> ../backup/$pgsip/pg_basetargz.log && tar -czvf ../backup/$pgsip/pg_basetargz/${tardate}_pgdata.tar.gz ./postgres/data/pgdata >> ../backup/$pgsip/pg_basetargz.log 2>&1
							/bin/echo $tardate >> ../backup/$pgsip/pg_basetargz.log && tar -czvf ../backup/$pgsip/pg_basetargz/${tardate}_store.tar.gz ./xwiki/data/store >> ../backup/$pgsip/pg_basetargz.log 2>&1
							/bin/echo $tardate >> ../backup/$pgsip/pg_basetargz.log && tar -czvf ../backup/$pgsip/pg_basetargz/${tardate}_extension.tar.gz ./xwiki/data/extension >> ../backup/$pgsip/pg_basetargz.log 2>&1
							echo "Сформированы архивы существующей Xwiki в ../backup/$pgsip/pg_basetargz/ :   ${tardate}_pgdata.tar.gz, ${tardate}_store.tar.gz, ${tardate}_extension.tar.gz"
							if [[ -f ../backup/$pgsip/pg_basetargz/$tardate_pgdata.tar.gz ]]; then
								tarsize1=$(du -sb ../backup/$pgsip/pg_basetargz/${tardate}_pgdata.tar.gz | awk '{ print $1 }')
								tarsize2=$(du -sb ../backup/$pgsip/pg_basetargz/${tardate}_store.tar.gz | awk '{ print $1 }')
								tarsize3=$(du -sb ../backup/$pgsip/pg_basetargz/${tardate}_extension.tar.gz | awk '{ print $1 }')
								if [[ $tarsize1>1000000 && $tarsize2>1000000 && $tarsize3>1000000 ]] ; then
									echo "Архив ../backup/$pgsip/pg_basetargz/${tardate}_pgdata.tar.gz размером $tarsize1 успешно создан"
									echo "Архив ../backup/$pgsip/pg_basetargz/${tardate}_store.tar.gz размером $tarsize2 успешно создан"
									echo "Архив ../backup/$pgsip/pg_basetargz/${tardate}_extension.tar.gz размером $tarsize3 успешно создан"
									rm -rf ./postgres/data/pgdata/*
									isrec=1
								else
									echo "В директории ../backup/$pgsip/pg_basetargz/ размер как миниум одного из архивов ${tardate}_pgdata.tar.gz, ${tardate}_store.tar.gz, ${tardate}_extension.tar.gz меньше 1000000"
									echo "Проверьте лог на ошибки: cat ../backup/$pgsip/pg_basetargz.log"
								fi
							else
								echo "В директории ../backup/$pgsip/pg_basetargz/ не создался как минимум один из архивов существующей БД ${tardate}_pgdata.tar.gz, ${tardate}_store.tar.gz, ${tardate}_extension.tar.gz"
								echo "Проверьте лог на ошибки: cat ../backup/$pgsip/pg_basetargz.log"
							fi
						else
							echo "Директория ./postgres/data/pgdata пустая, архив БД не запускался"
							isrec=1
						fi
						echo "Более подробную информацию по востановлению БД можно посмотреть в логе ../backup/$pgsip/pg_basetargz.log"
						if [[ $isrec==1 ]]; then
							/bin/echo "Recover from ../backup/$fromip/$pgsdate/base.tar.gz" >> ../backup/$pgsip/pg_basetargz.log && tar xvf ../backup/$fromip/$pgsdate/base.tar.gz -C ./postgres/data/pgdata >> ../backup/$pgsip/pg_basetargz.log
							/bin/echo "Recover from ../backup/$fromip/$pgsdate/pg_wal.tar.gz" >> ../backup/$pgsip/pg_basetargz.log && tar xvf ../backup/$fromip/$pgsdate/pg_wal.tar.gz -C ./postgres/data/pgdata/pg_wal >> ../backup/$pgsip/pg_basetargz.log
							/bin/echo "Recover from ../backup/$fromip/$pgsdate/xwiki_store.tar.gz" >> ../backup/$pgsip/pg_basetargz.log && tar xvf ../backup/$fromip/$pgsdate/xwiki_store.tar.gz -C ./xwiki/data >> ../backup/$pgsip/pg_basetargz.log
							/bin/echo "Recover from ../backup/$fromip/$pgsdate/xwiki_extension.tar.gz" >> ../backup/$pgsip/pg_basetargz.log && tar xvf ../backup/$fromip/$pgsdate/xwiki_extension.tar.gz -C ./xwiki/data >> ../backup/$pgsip/pg_basetargz.log
							sh xwiki_start.sh
							echo "Xwiki успешно восстановлена на дату $pgsdate"
							echo "Для восстановления Xwiki с бэкапа сервера $fromip на другое время, необходимо в качестве второго параметра указать название директории в виде даты, можно посмотреть выполнив команду: ls -la ../backup/$fromip/"
						fi
					else
						echo "Отсутствует директория для БД ./postgres/data/pgdata"
					fi
				else
					echo "Какой-то из файлов бэкапа backup_manifest, base.tar.gz, pg_wal.tar.gz, xwiki_store.tar.gz, xwiki_extension.tar.gz отсутствуют в директории ../backup/$fromip/$pgsdate"
					echo "Проверьте бэкап на ошибки или укажите другой бэкап в качестве второго параметра:"
					echo "ls -la ../backup/$fromip/$pgsdate/"
					echo "cat ../backup/$fromip/pg_basebackup.log* | more"
				fi
			else
				echo "Отсутствует директория с заданным бэкапом ../backup/$fromip/$pgsdate"
			fi
		else
			echo "Отсутсвует лог бэкапов ../backup/$fromip/pg_basebackup.log*"
		fi
	else
		echo "Отсутсвует директория ../backup/$fromip с бэкапами"
	fi
else
	echo "Вы не задали в качестве первого параметра хост, с которого хотите восстановить бэкап"
fi
