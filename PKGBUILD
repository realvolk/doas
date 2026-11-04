pkgname=doas-linux
pkgver=0.1.0
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
sha256sums=('70c0519a7f683b53de0eb32e22df49eeb07e162fd3e9b40e8f064ef60dae1b09')

build() {
    cd "$srcdir/doas-$pkgver"
    ./configure --prefix=/usr --sysconfdir=/etc
    make
}

package() {
    cd "$srcdir/doas-$pkgver"
    make DESTDIR="$pkgdir" install
}