#!/bin/bash

#example ./gradeit.sh dir1 dir2 logfile

INPUTS=${INPUTS:-"`seq 1 11`"}
ALGOS=${ALGOS:-" f  r  c  e  a  w"}
FRAMES=${FRAMES:-"16 31"}

DIR1=$1
DIR2=$2
LOG=${3:-${DIR2}/LOG.txt}

[[ ${#} -lt 2 ]] && echo "usage: $0 <refoutdir> <youroutdir>" && exit
[[ ! -d ${DIR1} ]] && echo "refoutdir <$DIR1> does not exist"  && exit
[[ ! -d ${DIR2} ]]  && echo "youroutdir <$DIR2> does not exist"  && exit

USEDIFF=${USEDIFF:-0}    # we are using cmp by default
DARGS=         # nothing
DARGS="-q --speed-large-files"  # the big files are killing us --> out of memory / fork refused etc
CHKSUM="md5sum"

declare -ai counters
declare -i x=0
for s in ${ALGOS}; do
        let counters[$x]=0
        let x=$x+1
done

rm -f ${LOG}

X1=`id -un`;X2=`id -ua`;X3=`hostname -s`;X4=$(date +"%m%d/%H%M");X5=`gcc -v 2>&1 | grep "^gcc" | cut -d' ' -f3` ; X6="/home/${X1}/${X2}/${X3}/${X4}/${X5}" ; X7=`echo ${X6} | ${CHKSUM}` ; echo "${X7} ${X6}" ; echo;

echo "input  frames   ${ALGOS}"

for I in ${INPUTS}; do
  for N in ${FRAMES}; do
    OUTLINE=`printf "%-7s %-7s" "${I}" "${N}"`
    x=0
    for A in ${ALGOS}; do 
	    OUTF="out${I}_${N}_${A}"
        if [[ ! -e ${DIR1}/${OUTF} ]]; then
            echo "${DIR1}/${OUTF} does not exist" >> ${LOG}
            OUTLINE=`printf "%s o" "${OUTLINE}"`
        elif [[ ! -e ${DIR2}/${OUTF} ]]; then
            echo "${DIR2}/${OUTF} does not exist" >> ${LOG}
            OUTLINE=`printf "%s o" "${OUTLINE}"`
        else 
	
            # echo "diff -b ${DARGS} ${DIR1}/${OUTF} ${DIR2}/${OUTF}"
            # diff hangs .. cmp does the same trick as we only what see whether it diffes
            if [[ ${USEDIFF} -eq 1 ]]; then
                DIFFCMD="diff -b ${DARGS} ${DIR1}/${OUTF} ${DIR2}/${OUTF}"
                DIFF=$(${DIFFCMD})
            else
                DIFFCMD="cmp ${DIR1}/${OUTF} ${DIR2}/${OUTF} 2>&1"
                DIFF=$(cmp ${DIR1}/${OUTF} ${DIR2}/${OUTF} 2>&1)
            fi
            if [[ $? == 0 ]]; then
                OUTLINE=`printf "%s  ." "${OUTLINE}"`
                let counters[$x]=`expr ${counters[$x]} + 1`
            else
                #echo "diff -b ${DARGS} ${DIR1}/${OUTF} ${DIR2}/${OUTF}" >> ${LOG}
                echo "${DIFFCMD}" >> ${LOG}
                SUMX=`egrep "^TOTAL" ${DIR1}/${OUTF}`
                SUMY=`egrep "^TOTAL" ${DIR2}/${OUTF}`
                echo "   DIR1-SUM ==> ${SUMX}" >> ${LOG}
                echo "   DIR2-SUM ==> ${SUMY}" >> ${LOG}
                OUTLINE=`printf "%s  #" "${OUTLINE}"`
            fi
        fi
	    let x=$x+1
    done
    echo "${OUTLINE}"
  done
done


OUTLINE=`printf "%-15s" "SUM"`
x=0
for A in ${ALGOS}; do 
    OUTLINE=`printf "%s %2d" "${OUTLINE}" "${counters[$x]}"`
    let x=$x+1
done
echo "${OUTLINE}"

