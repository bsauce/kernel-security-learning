for file in `find /usr/lib/debug -name '*.ko' -print`
do
        buildid=`eu-readelf -n $file| grep Build.ID: | awk '{print $3}'`
        dir=`echo $buildid | cut -c1-2`
        fn=`echo $buildid | cut -c3-`
        mkdir -p /usr/lib/debug/.build-id/$dir
        ln -s $file /usr/lib/debug/.build-id/$dir/$fn
        ln -s $file /usr/lib/debug/.build-id/$dir/${fn}.debug
done