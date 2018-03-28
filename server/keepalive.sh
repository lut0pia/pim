# Ensure this script is regularly run
if test -n "$USER" ; then
	echo "* * * * * "$USER" cd "`pwd`" && "$0 > /etc/cron.d/pim-ka
fi

# Remember credentials for future automatic runs
git config credential.helper store

git fetch
up_to_date=`git status | grep up-to-date`
pid=`pgrep pim-server`

if test -n "$pid" ; then
	echo "Server already running"
fi

if test -z "$up_to_date" ; then
	echo "Server out of date, updating..."
	git pull
fi

if test -z "$pid" || test -z "$up_to_date" ; then
	if test -n "$pid" ; then
		echo "Killing old server process"
		kill $pid
	fi
	echo "Starting new server process"
	nodejs main.js >> log.txt&
fi
