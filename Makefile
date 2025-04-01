gen:
	protoc --proto_path=./pb/ --go_out=./go pb/*.proto --go_opt=module=nagelbros.com/p2p2p