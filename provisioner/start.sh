#! /bin/sh

THISDIR="$( cd $(dirname $0); pwd)"
SCRIPT="$THISDIR/$(basename $0)"
PYENV="$THISDIR/pyenv"
TWISTD="$THISDIR/twistd.sh"
CONFD="$THISDIR/conf.d"

cd "$THISDIR"
. "$PYENV/bin/activate"
ls "$CONFD"/*.cfg | while read fname; do
    FNAME=$(basename "$fname")
    CONFIG="$CONFD/$FNAME"
    BASE=$(basename "$FNAME" .cfg)
    PIDFILE="$BASE.pid"
    "$TWISTD" --syslog --prefix "$BASE" --pidfile "$PIDFILE" provisioner -c "$CONFIG"
done

