import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import Omarchy.Pinentry 1.0

ShellRoot {
  id: root
  property var request: secureSession.valid ? JSON.parse(secureSession.metadata) : null
  property bool submitted: false
  property bool mismatch: false
  property var palette: ({})
  property var tokens: ({})
  property int cornerRadius: 0
  readonly property bool passwordMode: request !== null && request.mode === "getpin"
  readonly property bool repeatMode: passwordMode && request.repeat !== undefined
  readonly property bool inputRejected: password.rejected || (repeatMode && repeatPassword.rejected)
  readonly property color background: token("polkit.background", palette.background || "#121212")
  readonly property color foreground: token("polkit.text", palette.foreground || "#eeeeee")
  readonly property color accent: token("polkit.accent", palette.accent || "#ffd60a")
  readonly property color borderColor: token("polkit.border", accent)
  readonly property color errorColor: token("polkit.text-error", palette.red || "#e06060")
  readonly property string fontFamily: "JetBrainsMono Nerd Font"
  readonly property int fontSize: Number(token("font.icon-large", 22))

  SecureSession { id: secureSession }
  Component.onCompleted: {
    if (!secureSession.valid) Qt.quit()
    else Qt.callLater(() => root.passwordMode ? password.forceActiveFocus() : confirmation.forceActiveFocus())
  }

  function token(key, fallback) {
    let value = tokens[key]
    // Omarchy surface tokens can reference another section's color.
    for (let i = 0; i < 4 && typeof value === "string" && tokens[value] !== undefined; i++)
      value = tokens[value]
    return value === undefined ? fallback : value
  }

  function parseTheme(text) {
    const result = {}
    let section = ""
    for (const line of text.split("\n")) {
      const header = line.match(/^\s*\[([\w-]+)\]/)
      if (header) { section = header[1] + "."; continue }
      const entry = line.match(/^\s*([\w-]+)\s*=\s*(?:"([^"]*)"|([0-9.]+))/)
      if (entry) result[section + entry[1]] = entry[2] !== undefined ? entry[2] : Number(entry[3])
    }
    return result
  }

  function send(action) {
    if (submitted || !request) return
    const result = secureSession.submit(action === "accept")
    if (result === -2) {
      if (password.rejected) password.forceActiveFocus()
      else repeatPassword.forceActiveFocus()
      return
    }
    if (result === 0) {
      mismatch = true
      repeatPassword.forceActiveFocus()
      return
    }
    submitted = true
    Qt.quit()
  }

  FileView {
    path: Quickshell.env("HOME") + "/.local/state/omarchy/current/theme/colors.toml"
    watchChanges: true
    printErrors: false
    onFileChanged: reload()
    onLoaded: root.palette = root.parseTheme(text())
  }
  FileView {
    path: Quickshell.env("HOME") + "/.local/state/omarchy/current/theme/shell.toml"
    watchChanges: true
    printErrors: false
    onFileChanged: reload()
    onLoaded: root.tokens = root.parseTheme(text())
  }
  Process {
    command: ["/usr/bin/hyprctl", "getoption", "decoration:rounding", "-j"]
    running: true
    stdout: StdioCollector {
      onStreamFinished: {
        try { root.cornerRadius = JSON.parse(text).int || 0 } catch (_) {}
      }
    }
  }
  PanelWindow {
    id: panel
    visible: root.request !== null
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    exclusionMode: ExclusionMode.Ignore
    WlrLayershell.namespace: "pinentry-omarchy"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive

    Rectangle {
      anchors.fill: parent
      color: root.token("polkit.scrim", root.background)
      opacity: Number(root.token("polkit.scrim-alpha", 0.5))
    }
    MouseArea { anchors.fill: parent; onClicked: password.forceActiveFocus() }

    Rectangle {
      id: card
      anchors.centerIn: parent
      width: Math.min(420, panel.width - 48)
      height: content.height + 36
      radius: root.cornerRadius
      color: root.background
      border.color: root.inputRejected || root.mismatch || (root.request && root.request.error) ? root.errorColor : root.borderColor
      border.width: 2

      Column {
        id: content
        anchors.centerIn: parent
        width: parent.width - 36
        spacing: 14

        Text {
          width: parent.width
          text: root.request ? (root.request.title || qsTr("Authentication")) : ""
          textFormat: Text.PlainText
          color: root.accent
          font.family: root.fontFamily
          font.pixelSize: 13
          wrapMode: Text.Wrap
          maximumLineCount: 3
          elide: Text.ElideRight
        }
        Text {
          width: parent.width
          visible: text.length > 0
          text: root.request ? (root.request.desc || "") : ""
          textFormat: Text.PlainText
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: 12
          wrapMode: Text.Wrap
          maximumLineCount: 6
          elide: Text.ElideRight
        }
        Row {
          width: parent.width
          height: 42
          spacing: 14
          visible: root.passwordMode
          Text {
            width: 26
            height: parent.height
            text: "\uf023"
            color: root.accent
            font.family: root.fontFamily
            font.pixelSize: root.fontSize
            verticalAlignment: Text.AlignVCenter
          }
          Item {
            width: parent.width - 40
            height: parent.height
            SecureField {
              id: password
              session: secureSession
              field: 0
              anchors.fill: parent
              focus: true
              enabled: !root.submitted
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: root.fontSize
              clip: true
              onAccepted: root.repeatMode ? repeatPassword.forceActiveFocus() : root.send("accept")
              onCancelled: root.send("cancel")
              onNextField: root.repeatMode ? repeatPassword.forceActiveFocus() : password.forceActiveFocus()
            }
            Text {
              anchors.fill: parent
              visible: password.count === 0
              text: root.request ? (root.request.prompt || qsTr("Enter password")) : ""
              textFormat: Text.PlainText
              color: root.foreground
              opacity: 0.36
              font.family: root.fontFamily
              font.pixelSize: root.fontSize
              verticalAlignment: Text.AlignVCenter
              elide: Text.ElideRight
            }
          }
        }
        Item {
          visible: root.repeatMode
          width: parent.width
          height: 42
          SecureField {
            id: repeatPassword
            session: secureSession
            field: 1
            anchors.fill: parent
            enabled: !root.submitted
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: root.fontSize
            clip: true
            onAccepted: root.send("accept")
            onCancelled: root.send("cancel")
            onNextField: password.forceActiveFocus()
          }
          Text {
            anchors.fill: parent
            visible: repeatPassword.count === 0
            text: root.request ? (root.request.repeat || qsTr("Repeat password")) : ""
            textFormat: Text.PlainText
            color: root.foreground
            opacity: 0.36
            font.family: root.fontFamily
            font.pixelSize: 16
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
          }
        }
        Text {
          width: parent.width
          visible: text.length > 0
          text: root.inputRejected ? qsTr("Password input was rejected. Maximum length: 4096 UTF-8 bytes. Press Ctrl+U in that field and re-enter it.") : root.mismatch ? (root.request.repeaterror || qsTr("Passwords do not match")) : (root.request ? (root.request.error || "") : "")
          textFormat: Text.PlainText
          color: root.errorColor
          font.family: root.fontFamily
          font.pixelSize: 12
          wrapMode: Text.Wrap
        }
        Row {
          visible: !root.passwordMode
          spacing: 16
          Repeater {
            model: root.request && (root.request.mode === "message" || root.request.oneButton) ? ["accept"] : ["accept", "cancel"]
            Rectangle {
              required property string modelData
              width: buttonLabel.implicitWidth + 24
              height: 32
              color: mouse.containsMouse ? root.accent : root.background
              border.color: root.accent
              radius: Math.min(4, root.cornerRadius)
              Text {
                id: buttonLabel
                anchors.centerIn: parent
                text: parent.modelData === "accept" ? (root.request.ok || qsTr("OK")) : (root.request.cancel || qsTr("Cancel"))
                textFormat: Text.PlainText
                color: mouse.containsMouse ? root.background : root.foreground
                font.family: root.fontFamily
                font.pixelSize: 13
              }
              MouseArea { id: mouse; anchors.fill: parent; hoverEnabled: true; onClicked: root.send(parent.modelData) }
            }
          }
        }
        Text {
          text: root.passwordMode ? qsTr("Enter to unlock · Esc to cancel") : qsTr("Enter to confirm · Esc to cancel")
          color: root.foreground
          opacity: 0.45
          font.family: root.fontFamily
          font.pixelSize: 10
        }
      }
    }
    Item {
      id: confirmation
      anchors.fill: parent
      visible: !root.passwordMode
      focus: !root.passwordMode
      Keys.onReturnPressed: root.send("accept")
      Keys.onEnterPressed: root.send("accept")
      Keys.onEscapePressed: root.send("cancel")
    }
  }
}
