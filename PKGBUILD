pkgname=doas-linux
pkgver=0.1.1
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
sha256sums=('dea158f150673a76bde9aa907bad0ab749eb3419645fe8f67df6af7b4d545f84')

build() {
    cd "$srcdir/doas-$pkgver"
    ./configure --prefix=/usr --sysconfdir=/etc
    make
}

package() {
    cd "$srcdir/doas-$pkgver"
    make DESTDIR="$pkgdir" install
}