#!/bin/bash
#
#       /etc/rc.d/init.d/freeswitch
#
#       The FreeSwitch Open Source Voice Platform
#
#  chkconfig: 345 89 14
#  description: Starts and stops the freeswitch server daemon
#  processname: freeswitch
#  config: /usr/local/freeswitch/conf/freeswitch.conf
#  pidfile: /usr/local/freeswitch/run/freeswitch.pid

### BEGIN INIT INFO
# Provides: freeswitch
# Required-Start: wanrouter
# Required-Stop: wanrouter
# Should-Start: wanrouter
# Should-Stop: wanrouter
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: FreeSWITCH
# Description: The FreeSWITCH Communications Platform
### END INIT INFO

# Source function library.
. /etc/init.d/functions

PROG_NAME=freeswitch
PID_FILE=${PID_FILE-/usr/local/freeswitch/run/init.freeswitch.pid}
FS_USER=${FS_USER-root}
FS_FILE=${FS_FILE-/usr/local/freeswitch/bin/freeswitch} 
FS_HOME=${FS_HOME-/usr/local/freeswitch/run}
LOCK_FILE=/var/lock/subsys/freeswitch
FREESWITCH_ARGS="-nc -nonat"
RETVAL=0

# Source usr/localions file
if [ -f /etc/sysconfig/freeswitch ]; then
	. /etc/sysconfig/freeswitch
fi

# <define any local shell functions used by the code that follows>

start() {
        echo -n "Starting $PROG_NAME: "
        if [ -e $LOCK_FILE ]; then
            if [ -e $PID_FILE ] && [ -e /proc/`cat $PID_FILE` ]; then
                echo
                echo -n $"$PROG_NAME is already running.";
                failure $"$PROG_NAME is already running.";
                echo
                return 1
            fi
        fi
	cd $FS_HOME
        daemon --user $FS_USER --pidfile $PID_FILE "$FS_FILE $FREESWITCH_ARGS $FREESWITCH_PARAMS >/dev/null 2>&1"
		RETVAL=$?
		echo
        [ $RETVAL -eq 0 ] && touch $LOCK_FILE;
	echo
        return $RETVAL
}

stop() {
        echo -n "Shutting down $PROG_NAME: "
        if [ ! -e $LOCK_FILE ]; then
            echo
            echo -n $"cannot stop $PROG_NAME: $PROG_NAME is not running."
            failure $"cannot stop $PROG_NAME: $PROG_NAME is not running."
            echo
            return 1;
        fi
	cd $FS_HOME
	$FS_FILE -stop > /dev/null 2>&1
        killproc $PROG_NAME
	RETVAL=$?
	echo
	[ $RETVAL -eq 0 ] &&  rm -f $LOCK_FILE;
        return $RETVAL
}

rhstatus() {
	status $PROG_NAME;
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    status)
        status $PROG_NAME
	RETVAL=$?
        ;;
    restart)
        stop
        start
        ;;
    reload)
#        <cause the service configuration to be reread, either with
#        kill -HUP or by restarting the daemons, in a manner similar
#        to restart above>
        ;;
    condrestart)
        [ -f $PID_FILE ] && restart || :
	;;
    *)
        echo "Usage: $PROG_NAME {start|stop|status|reload|restart}"
        exit 1
        ;;
esac
exit $RETVAL
