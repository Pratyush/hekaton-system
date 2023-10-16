#!/bin/bash

set -eu

TOPSCRATCHDIR="/scratch/zt1/project/imiers-prj/shared/"

HELPSTR="\
Usage:\n\
    janus_cache_g16_keys [pk|ck] <bench_desc> \
"

if [ -z ${1+x} ] || [ -z ${2+x} ]; then
    echo -e "$HELPSTR"
    exit 1
fi

KEYTYPE=$1
BENCH_DESC=$2

# Global scratch space
SCRATCHDIR="$TOPSCRATCHDIR/$BENCH_DESC"
# Local scratch space
LOCAL_SCRATCHDIR="/tmp/${USER}-${BENCH_DESC}"
mkdir -p $LOCAL_SCRATCHDIR

# Globally, everything is in g16_pks/. We differentiate locally though
REMOTEKEYDIR="$SCRATCHDIR/g16_pks"
KEYDIR="$LOCAL_SCRATCHDIR/g16_${KEYTYPE}s"

REMOTE_REQDIR="$SCRATCHDIR/reqs"
LOCAL_REQDIR="$LOCAL_SCRATCHDIR/reqs"

# Make a temporary KEYDIR so that once KEYDIR exists, it's ready to be used
TEMP_KEYDIR="$LOCAL_SCRATCHDIR/tmp_g16_${KEYTYPE}s"

# Before anything, we need to transfer over some files from global scratch
# if they haven't already been transferred. Check if they have
if [[ ! -d "$KEYDIR" ]]; then
	echo "Local cache doesn't exist"

	# If the Groth16 pubkeys don't exist, try to fetch them

	# Try to allocate a lockfile
	echo "Allocating a lock file"
	TEMPFILE=$(mktemp ./tmplockfile.XXXX --tmpdir=$LOCAL_SCRATCHDIR)
	LOCKFILE="$LOCAL_SCRATCHDIR/transfer.lock"
	echo "Linking $LOCKFILE -> $TEMPFILE"
	if ln "$TEMPFILE" "$LOCKFILE" 2> /dev/null ; then
		# On success, do the transfer
		echo "Transferring Groth16 keys..."

		mkdir $TEMP_KEYDIR
		mkdir -p $LOCAL_REQDIR

		NUM_SUBCIRCUITS=$(echo -n "$BENCH_DESC" | cut -d_ -f2 | tr -d [:alpha:])
		LAST_PARENT_IDX=$(($NUM_SUBCIRCUITS - 3))
		ROOT_IDX=$(($NUM_SUBCIRCUITS - 2))
		PADDING_IDX=$(($NUM_SUBCIRCUITS - 1))

		# Copy leaf keys
		cp "$REMOTEKEYDIR/g16_${KEYTYPE}_0.bin" "$TEMP_KEYDIR/g16_${KEYTYPE}_0.bin"
		cp "$REMOTEKEYDIR/g16_${KEYTYPE}_1.bin" "$TEMP_KEYDIR/g16_${KEYTYPE}_1.bin"
		# Copy the rest
		cp "$REMOTEKEYDIR/g16_${KEYTYPE}_$LAST_PARENT_IDX.bin" "$TEMP_KEYDIR/g16_${KEYTYPE}_$LAST_PARENT_IDX.bin"
		cp "$REMOTEKEYDIR/g16_${KEYTYPE}_$ROOT_IDX.bin" "$TEMP_KEYDIR/g16_${KEYTYPE}_$ROOT_IDX.bin"
		cp "$REMOTEKEYDIR/g16_${KEYTYPE}_$PADDING_IDX.bin" "$TEMP_KEYDIR/g16_${KEYTYPE}_$PADDING_IDX.bin"

		# Now symlink every other PK/CK to the existing copies
		# Do the leaves
		echo "Hardlinking leaves..."
		for i in $(seq 2 $(($NUM_SUBCIRCUITS / 2 - 1))); do
			ln "$TEMP_KEYDIR/g16_${KEYTYPE}_1.bin" "$TEMP_KEYDIR/g16_${KEYTYPE}_$i.bin"
		done
		# Do the parents
		echo "Hardlinking parents..."
		for i in $(seq $(($NUM_SUBCIRCUITS / 2)) $(($LAST_PARENT_IDX - 1))); do
			ln "$TEMP_KEYDIR/g16_${KEYTYPE}_$LAST_PARENT_IDX.bin" "$TEMP_KEYDIR/g16_${KEYTYPE}_$i.bin"
		done

		# Now sync the requests
		rsync -aq "$REMOTE_REQDIR/" "$LOCAL_REQDIR/"

		# All done. Rename the KEYDIR and remove the lockfile
		mv $TEMP_KEYDIR $KEYDIR
		rm $LOCKFILE
	else
		# If the lock exists, someone else is doing the transfer.
		# Wait until they're done
		echo "Lockfile exists. Waiting for lockfile to be deleted"
		while [[ -f "$LOCKFILE" ]]; do
			sleep 1
		done
	fi

	rm "$TEMPFILE"
else
	echo $KEYDIR exists
fi

# By this point, we're guaranteed that $LOCAL_SCRATCHDIR/g16_[pk|ck]s is populated

echo "Done"
