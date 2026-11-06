pkgname=doas-linux
pkgver=0.1.2
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
sha256sums=('7b862a490b20bf2e73ce1d0368fbec4ca0e51ee46b5b222ca11bcdd79c5adab9')

build() {
    cd "$srcdir/doas-$pkgver"
    ./configure --prefix=/usr --sysconfdir=/etc
    make
}

package() {
    cd "$srcdir/doas-$pkgver"
    make DESTDIR="$pkgdir" install
}