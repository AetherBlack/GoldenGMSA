![](./.github/banner.png)

<p align="center">
    A python script to list gMSA account and KDS Key.
    <br>
    <img alt="PyPI" src="https://img.shields.io/pypi/v/GoldenGMSA">
    <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/AetherBlack/GoldenGMSA">
    <a href="https://twitter.com/intent/follow?screen_name=san__yohan" title="Follow"><img src="https://img.shields.io/twitter/follow/san__yohan?label=AetherBlack&style=social"></a>
    <br>
</p>

## Installation

You can install it from pypi (latest version is <img alt="PyPI" src="https://img.shields.io/pypi/v/GoldenGMSA">) with this command:

```bash
sudo python3 -m pip install GoldenGMSA
```

OR from source :

```bash
git clone https://github.com/AetherBlack/GoldenGMSA
cd GoldenGMSA
sudo python3 -m pip install -r requirements.txt
sudo python3 setup.py install
```

OR with pipx :

```bash
python3 -m pipx install git+https://github.com/AetherBlack/GoldenGMSA/
```

## Examples

- You want to list gMSA accounts with Kerberos Authentication:

```bash
GoldenGMSA -k -use-ldaps -port 636 gmsainfo $DOMAIN/$USER:"$PASSWORD"@$KDC
```

![](./docs/img/1.png)

- You want to list KDS Key:

```bash
GoldenGMSA kdsinfo $DOMAIN/$USER:$PASSWORD
```

![](./docs/img/2.png)

- You want to list gMSA accounts:

```bash
GoldenGMSA gmsainfo $DOMAIN/$USER:$PASSWORD
```

![](./docs/img/3.png)


## How it works

The tool will connect to the DC's LDAP to list gMSA and their `msDS-ManagedPassword` if possible.

---

## Credits

- [@Semperis](https://github.com/Semperis) for developping [GoldenGMSA in C#](https://github.com/Semperis/GoldenGMSA)
- [@fortra](https://github.com/fortra/) for developping [impacket](https://github.com/fortra/impacket)

## License

[GNU General Public License v3.0](./LICENSE)
