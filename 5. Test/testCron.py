from crontab import CronTab

cron = CronTab(user='root')
job = cron.new(command='/usr/bin/python /home/testPrint.py', comment='test')

job.minute.every(1) 
cron.write()
print cron.render()
