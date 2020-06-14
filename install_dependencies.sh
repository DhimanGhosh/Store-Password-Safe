case "$OSTYPE" in
    linux*)
		sudo apt-get -y update
		pip install -r requirements.txt ;;
    msys*)
		pip install --upgrade pip wheel setuptools virtualenv
		pip install -r requirements.txt ;;
esac
