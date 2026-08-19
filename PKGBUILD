# Maintainer:  <security@d5data.ai>

pkgname=aimap
pkgver=1.9.21
pkgrel=1
groups=('blackarch' 'blackarch-scanner' 'blackarch-recon' 'blackarch-networking')
pkgdesc='Security scanner for AI and ML infrastructure. 120 fingerprints + 50 deep enumerators across LLM runtimes, vector databases, model servers, agent platforms, observability stacks, AI safety/guardrails, medical AI, and voice/audio AI. Surfaces unauthenticated services, exposed credentials, PII, and claimable admin states.'
arch=('x86_64' 'aarch64')
url='https://github.com/Nicholas-Kloster/aimap'
license=('MIT')
makedepends=('go')
source=("$pkgname-$pkgver.tar.gz::https://github.com/Nicholas-Kloster/aimap/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
  cd "$pkgname-$pkgver"
  export CGO_ENABLED=0
  export GOFLAGS="-trimpath -mod=readonly -modcacherw"
  export LDFLAGS="-buildmode=pie -linkmode=external -s -w"
  go build -o "$pkgname" .
}

package() {
  cd "$pkgname-$pkgver"

  # Binary
  install -Dm755 "$pkgname" "$pkgdir/usr/bin/$pkgname"

  # Man page
  if [ -f "aimap.1" ]; then
    install -Dm644 "aimap.1" "$pkgdir/usr/share/man/man1/aimap.1"
  fi

  # License
  install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"

  # Documentation
  install -Dm644 "README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
