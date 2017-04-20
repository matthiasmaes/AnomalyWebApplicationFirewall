from crontab import CronTab
import datetime

cron = CronTab(user='root')
job = cron.new(command='/usr/bin/python /home/testPrint.py', comment='test')

#job.minute.every(1) 
job.setall(datetime.datetime((2017,04,20,15,00)))
cron.write()
print cron.render()
