RabbitMQ setup:

[lgs@t430s eduid-am]$ sudo rabbitmqctl add_user eduid eduid
[sudo] password for lgs: 
Creating user "eduid" ...
...done.
[lgs@t430s eduid-am]$ sudo rabbitmqctl add_vhost eduid_vhost
Creating vhost "eduid_vhost" ...
...done.
[lgs@t430s eduid-am]$ sudo rabbitmqctl set_permissions -p eduid_vhost eduid ".*" ".*" ".*"
Setting permissions for user "eduid" in vhost "eduid_vhost" ...
...done.


How to run it:

Create a eduid_am.ini config file (there are templates in the config-templates directory)

celery worker --app=eduid_am
