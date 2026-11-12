pkgname=doas-linux
pkgver=0.1.3
pkgrel=1
pkgdesc="Linux port of OpenBSD doas(1)"
arch=('x86_64')
url="https://github.com/realvolk/doas"
license=('ISC')
depends=('libbsd' 'pam')
makedepends=('byacc')
provides=('doas')
conflicts=('doas' 'opendoas')
source=("$pkgname-$pkgver.tar.gz::https://github.com/realvolk/doas/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('357875180d3ab1fd93a11e574a20b7354fd5e1be0e1c02c6b54fe461550e7551')

build() {
    cd "$srcdir/doas-$pkgver"
    ./configure --prefix=/usr --sysconfdir=/etc
    make
}

package() {
    cd "$srcdir/doas-$pkgver"
    make DESTDIR="$pkgdir" install
}