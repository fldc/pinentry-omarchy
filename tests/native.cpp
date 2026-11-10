// Compile the actual field implementation and its generated moc into an
// offscreen test executable. No compositor input injection is used.
#include "../native/plugin.cpp"
#include <QTemporaryDir>
#include <QtGui/qpa/qwindowsysteminterface.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <thread>
#include <cstdlib>
#include <cstdio>

static void requireCondition(bool condition, int line) {
  if (!condition) { std::fprintf(stderr, "Native field regression failed at line %d\n", line); std::abort(); }
}
#define require(condition) requireCondition((condition), __LINE__)

static void readExact(int fd, char *data, size_t length) {
  while (length) {
    const auto count = ::read(fd, data, length);
    require(count > 0);
    data += count;
    length -= size_t(count);
  }
}

static void writeExact(int fd, const char *data, size_t length) {
  while (length) {
    const auto count = ::write(fd, data, length);
    require(count > 0);
    data += count;
    length -= size_t(count);
  }
}

class Backend {
public:
  explicit Backend(bool repeat) {
    require(directory.isValid());
    const QByteArray path = (directory.path() + "/ui.sock").toUtf8();
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    require(size_t(path.size()) < sizeof(address.sun_path));
    std::memcpy(address.sun_path, path.constData(), size_t(path.size()));
    const int listener = ::socket(AF_UNIX, SOCK_STREAM, 0);
    require(listener >= 0);
    require(::bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    require(::listen(listener, 1) == 0);
    qputenv("PINENTRY_OMARCHY_SOCKET", path);
    qputenv("PINENTRY_OMARCHY_PARENT", QByteArray::number(::getpid()));
    worker = std::thread([listener, repeat] {
      const int client = ::accept(listener, nullptr, nullptr);
      require(client >= 0);
      ::close(listener);
      const QByteArray metadata = repeat ? "{\"mode\":\"getpin\",\"repeat\":\"Again\"}" : "{\"mode\":\"getpin\"}";
      const auto length = htonl(uint32_t(metadata.size()));
      writeExact(client, reinterpret_cast<const char *>(&length), sizeof(length));
      writeExact(client, metadata.constData(), size_t(metadata.size()));
      unsigned char accepted;
      uint32_t responseLength;
      readExact(client, reinterpret_cast<char *>(&accepted), 1);
      readExact(client, reinterpret_cast<char *>(&responseLength), sizeof(responseLength));
      require(accepted == 1 && ntohl(responseLength) == 10);
      char response[10];
      readExact(client, response, sizeof(response));
      require(std::memcmp(response, "re-entered", sizeof(response)) == 0);
      writeExact(client, "done\n", 5);
      ::close(client);
    });
  }
  ~Backend() { worker.join(); }
private:
  QTemporaryDir directory;
  std::thread worker;
};

static void key(SecureField &field, int code, const QString &text = {},
                Qt::KeyboardModifiers modifiers = Qt::NoModifier) {
  QKeyEvent event(QEvent::KeyPress, code, modifiers, text);
  QCoreApplication::sendEvent(&field, &event);
}

static void overflowAndReentry(bool repeat) {
  Backend backend(repeat);
  SecureSession session;
  require(session.valid());
  QQuickWindow window;
  window.setGeometry(0, 0, 420, 240);
  window.show();
  // The offscreen platform has no compositor to grant focus. Deliver its focus
  // notification inside this process; production still requires real focus.
  QWindowSystemInterface::handleFocusWindowChanged(&window);
  QWindowSystemInterface::sendWindowSystemEvents(QEventLoop::AllEvents);
  QCoreApplication::processEvents();
  require(window.isActive());
  SecureField first(window.contentItem()), second(window.contentItem());
  first.setSessionObject(&session);
  second.setSessionObject(&session);
  require(second.setProperty("field", 1));
  first.forceActiveFocus();
  // Exactly 4096 UTF-8 bytes, then a suffix which must never be submitted.
  key(first, Qt::Key_unknown, QString(2048, QChar(0x00e9)));
  require(first.count() == 2048 && !first.rejected());
  key(first, Qt::Key_X, "x");
  require(first.rejected() && session.submit(true) == -2);
  key(first, Qt::Key_Backspace);
  require(first.rejected() && session.submit(true) == -2);
  if (repeat) {
    key(second, Qt::Key_unknown, QString(2048, QChar(0x00e9)));
    key(second, Qt::Key_Y, "y");
    require(second.rejected() && session.submit(true) == -2);
  }
  key(first, Qt::Key_U, {}, Qt::ControlModifier);
  require(!first.rejected() && first.count() == 0);
  key(first, Qt::Key_unknown, "re-entered");
  if (repeat) {
    require(session.submit(true) == -2);
    key(second, Qt::Key_U, {}, Qt::ControlModifier);
    key(second, Qt::Key_unknown, "re-entered");
  }
  require(session.submit(true) == 1);
  require(first.count() == 0 && second.count() == 0);
}

int main(int argc, char **argv) {
  QGuiApplication application(argc, argv);
  overflowAndReentry(false);
  overflowAndReentry(true);
  std::puts("Offscreen native field tests passed");
}
