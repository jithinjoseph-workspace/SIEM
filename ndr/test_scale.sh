ENGINE="ndr-engine-1"
NEW_ENGINE="ndr-engine-4"
NEW_INSTANCE_ID="4"

IMAGE=$(docker inspect --format '{{.Config.Image}}' $ENGINE)
NETWORK=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' $ENGINE)
BINDS=$(docker inspect --format '{{range .HostConfig.Binds}}-v {{.}} {{end}}' $ENGINE)
ENVS=$(docker inspect --format '{{range .Config.Env}}-e {{.}} {{end}}' $ENGINE | sed "s/INSTANCE_ID=[0-9]*/INSTANCE_ID=$NEW_INSTANCE_ID/")

echo "docker run -d --name $NEW_ENGINE --privileged --network $NETWORK $BINDS $ENVS $IMAGE"
