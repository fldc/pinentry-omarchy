#include <QQmlExtensionPlugin>
#include <QQuickPaintedItem>
#include <QQuickWindow>
#include <QPainter>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QGuiApplication>
#include <QTimer>
#include <QPointer>
#include <cstring>

extern "C" {
void *pe_open();
void pe_close(void *);
const char *pe_metadata(const void *);
bool pe_insert(void *, size_t, const unsigned char *, size_t);
void pe_edit(void *, size_t, int);
size_t pe_count(const void *, size_t, bool);
bool pe_rejected(const void *, size_t);
int pe_submit(void *, bool);
}

class SecureSession : public QObject {
  Q_OBJECT
  Q_PROPERTY(QString metadata READ metadata CONSTANT)
  Q_PROPERTY(bool valid READ valid CONSTANT)
public:
  explicit SecureSession(QObject *parent = nullptr) : QObject(parent), handle(pe_open()) {}
  ~SecureSession() override { if (handle) pe_close(handle); }
  QString metadata() const { return handle ? QString::fromUtf8(pe_metadata(handle)) : QString(); }
  bool valid() const { return handle != nullptr; }
  Q_INVOKABLE int submit(bool accept) {
    const int result = handle ? pe_submit(handle, accept) : -1;
    emit cleared();
    return result;
  }
  void *handle;
signals:
  void cleared();
};

// Only bullet counts leave this item. There is deliberately no text property,
// clipboard API, input-method support, undo stack, or accessibility text value.
class SecureField : public QQuickPaintedItem {
  Q_OBJECT
  Q_PROPERTY(SecureSession *session READ sessionObject WRITE setSessionObject)
  Q_PROPERTY(int field MEMBER field)
  Q_PROPERTY(QColor color MEMBER color)
  Q_PROPERTY(QFont font MEMBER font)
  Q_PROPERTY(int count READ count NOTIFY changed)
  Q_PROPERTY(bool rejected READ rejected NOTIFY changed)
public:
  explicit SecureField(QQuickItem *parent = nullptr) : QQuickPaintedItem(parent) {
    setFlag(ItemIsFocusScope, true);
    setFlag(ItemAcceptsInputMethod, false);
    setAcceptedMouseButtons(Qt::LeftButton);
    setActiveFocusOnTab(true);
    connect(this, &QQuickItem::activeFocusChanged, this, [this] { update(); });
    connect(this, &QQuickItem::windowChanged, this, [this](QQuickWindow *window) {
      if (!window) return;
      seenActive = window->isActive();
      connect(window, &QWindow::activeChanged, this, [this, window] {
        if (window->isActive()) seenActive = true;
        else if (seenActive && session) {
          // Do not retain a half-entered secret across a lock or focus takeover.
          session->submit(false);
          QCoreApplication::quit();
        }
      });
    });
  }
  void componentComplete() override {
    QQuickPaintedItem::componentComplete();
    if (session) connect(session, &SecureSession::cleared, this, [this] { emit changed(); update(); });
  }
  int count() const { return session && session->handle ? int(pe_count(session->handle, field, false)) : 0; }
  bool rejected() const { return session && session->handle && pe_rejected(session->handle, field); }
  SecureSession *sessionObject() const { return session.data(); }
  void setSessionObject(SecureSession *value) { session = value; }
  void paint(QPainter *painter) override {
    painter->setFont(font);
    painter->setPen(color);
    const QFontMetricsF metrics(font);
    const qreal step = metrics.horizontalAdvance(QChar(0x2022));
    const int cursor = session && session->handle ? int(pe_count(session->handle, field, true)) : 0;
    const qreal offset = qMax(qreal(0), step * cursor - width() + 4);
    painter->setClipRect(boundingRect());
    painter->drawText(QRectF(-offset, 0, step * count() + width(), height()), Qt::AlignLeft | Qt::AlignVCenter, QString(count(), QChar(0x2022)));
    if (hasActiveFocus()) {
      const qreal x = step * cursor - offset;
      painter->drawLine(QPointF(x, (height() - metrics.height()) / 2), QPointF(x, (height() + metrics.height()) / 2));
    }
  }
protected:
  void mousePressEvent(QMouseEvent *event) override {
    forceActiveFocus();
    event->accept();
  }
  void keyPressEvent(QKeyEvent *event) override {
    if (!session || !session->handle || !window() || !window()->isActive()) { event->accept(); return; }
    const int key = event->key();
    if (key == Qt::Key_Return || key == Qt::Key_Enter) { emit accepted(); event->accept(); return; }
    if (key == Qt::Key_Escape) { emit cancelled(); event->accept(); return; }
    if (key == Qt::Key_Tab || key == Qt::Key_Backtab) { emit nextField(); event->accept(); return; }
    int operation = -1;
    switch (key) {
      case Qt::Key_Backspace: operation = 0; break;
      case Qt::Key_Delete: operation = 1; break;
      case Qt::Key_Left: operation = 2; break;
      case Qt::Key_Right: operation = 3; break;
      case Qt::Key_Home: operation = 4; break;
      case Qt::Key_End: operation = 5; break;
      default: break;
    }
    if ((event->modifiers() & Qt::ControlModifier) && key == Qt::Key_U) operation = 6;
    if (operation >= 0) pe_edit(session->handle, field, operation);
    else if (!(event->modifiers() & (Qt::ControlModifier | Qt::MetaModifier)) && !event->text().isEmpty()) {
      QByteArray text = event->text().toUtf8();
      pe_insert(session->handle, field, reinterpret_cast<const unsigned char *>(text.constData()), size_t(text.size()));
      // This transient key-event conversion never contains accumulated input.
      volatile char *bytes = text.data();
      for (qsizetype i = 0; i < text.size(); ++i) bytes[i] = 0;
    }
    emit changed();
    update();
    event->accept();
  }
signals:
  void changed();
  void accepted();
  void cancelled();
  void nextField();
private:
  QPointer<SecureSession> session;
  int field = 0;
  QColor color = Qt::white;
  QFont font;
  bool seenActive = false;
};

class PinentryPlugin : public QQmlExtensionPlugin {
  Q_OBJECT
  Q_PLUGIN_METADATA(IID QQmlExtensionInterface_iid)
public:
  void registerTypes(const char *uri) override {
    qmlRegisterType<SecureSession>(uri, 1, 0, "SecureSession");
    qmlRegisterType<SecureField>(uri, 1, 0, "SecureField");
  }
};

#include "plugin.moc"
