/*
 * SPDX-FileCopyrightText: 2018 Red Hat Inc
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 * SPDX-FileCopyrightText: 2018 Jan Grulich <jgrulich@redhat.com>
 * SPDX-FileCopyrightText: 2022 Harald Sitter <sitter@kde.org>
 * SPDX-FileCopyrightText: 2022 Harald Sitter <sitter@kde.org>
 * SPDX-FileCopyrightText: 2024 David Redondo <kde@david-redondo.de>
 */

#include "inputcapture.h"
#include "inputcapture_debug.h"

#include "session.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusReply>
#include <QGuiApplication>

using namespace Qt::StringLiterals;

QDBusArgument &operator<<(QDBusArgument &argument, const InputCapturePortal::zone &zone)
{
    argument.beginStructure();
    argument << zone.width << zone.height << zone.x_offset << zone.y_offset;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, InputCapturePortal::zone &zone)
{
    argument.beginStructure();
    argument >> zone.width >> zone.height >> zone.x_offset >> zone.y_offset;
    argument.endStructure();
    return argument;
}

InputCapturePortal::InputCapturePortal(QObject *parent)
    : QDBusAbstractAdaptor(parent)
{
    qDBusRegisterMetaType<zone>();
    qDBusRegisterMetaType<QList<zone>>();
    qDBusRegisterMetaType<QList<QMap<QString, QVariant>>>();
}

InputCapturePortal::~InputCapturePortal() noexcept
{
}

uint InputCapturePortal::CreateSession(const QDBusObjectPath &handle,
                                       const QDBusObjectPath &session_handle,
                                       const QString &app_id,
                                       const QString &parent_window,
                                       const QVariantMap &options,
                                       QVariantMap &results)
{
    Q_UNUSED(results);
    qCDebug(XdgDesktopPortalKdeInputCapture) << "CreateSession called with parameters:";
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    handle: " << handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    session_handle: " << session_handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    app_id: " << app_id;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    parent_window: " << parent_window;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    options: " << options;

    InputCaptureSession *session = static_cast<InputCaptureSession *>(Session::createSession(this, Session::InputCapture, app_id, session_handle.path()));

    const uint requestedCapabilties = options.value("capabilities").toUInt();
    qDebug() << options.value("capabilities") << options.value("capabilities").toUInt();
    if (requestedCapabilties == 0) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "No capabilities requested";
        return 2;
    }

    session->setCapabilities(Capabilities::fromInt(requestedCapabilties));

    if (!session) {
        return 2;
    }

    results.insert(u"capabilities"_s, static_cast<uint>(session->capabilities()));
    return 0;
}

uint InputCapturePortal::GetZones(const QDBusObjectPath &handle,
                                  const QDBusObjectPath &session_handle,
                                  const QString &app_id,
                                  const QVariantMap &options,
                                  QVariantMap &results)
{
    Q_UNUSED(results);
    qCDebug(XdgDesktopPortalKdeInputCapture) << "GetZones called with parameters:";
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    handle: " << handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    session_handle: " << session_handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    app_id: " << app_id;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    options: " << options;

    InputCaptureSession *session = qobject_cast<InputCaptureSession *>(Session::getSession(session_handle.path()));

    if (!session) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Tried to get zones on non-existing session " << session_handle.path();
        return 2;
    }

    results.insert("zone_set", 0u);
    QList<zone> zones;
    for (const auto screen : qGuiApp->screens()) {
        zones.push_back(zone{
            .width = static_cast<uint>(screen->geometry().width()),
            .height = static_cast<uint>(screen->geometry().height()),
            .x_offset = screen->geometry().x(),
            .y_offset = screen->geometry().y(),
        });
    }
    results.insert("zones", QVariant::fromValue(zones));
    return 0;
}

static bool checkBarrier(int x1, int y1, int x2, int y2, uint id)
{
    // Only allow barriers fully on a edge of a screen with no other screen next it
    QScreen *barrierScreen = nullptr;
    bool transpose = false;
    if (x1 != x2) {
        std::swap(x1, y1);
        std::swap(x2, y2);
        transpose = true;
    }
    if (y1 > y2) {
        std::swap(y1, y2);
    }
    for (const auto screen : qGuiApp->screens()) {
        auto geometry = screen->geometry();
        if (transpose) {
            geometry = geometry.transposed();
            geometry.moveTo(geometry.y(), geometry.x());
        }

        if (y1 > geometry.bottom() || geometry.y() > y2) {
            continue;
        }
        if (x1 == geometry.x() || x1 == geometry.x() + geometry.width()) {
            if (y1 == geometry.y() && y2 == geometry.bottom()) {
                barrierScreen = screen;
            } else {
                // the edge one or doesnt fill the edge or this is a screen next to the intended one
                // either way we dont allow it
                qCWarning(XdgDesktopPortalKdeInputCapture) << "Barrier" << id << "doesnt fill or on edge to another screen";
                return false;
            }
        }
    }

    if (!barrierScreen) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Barrier" << id << "not on any screen edge";
        return false;
    }
    return true;
}

uint InputCapturePortal::SetPointerBarriers(const QDBusObjectPath &handle,
                                            const QDBusObjectPath &session_handle,
                                            const QString &app_id,
                                            const QVariantMap &options,
                                            const QList<QVariantMap> &barriers,
                                            uint zone_set,
                                            QVariantMap &results)
{
    qCDebug(XdgDesktopPortalKdeInputCapture) << "SetPointerBarriers called with parameters:";
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    handle: " << handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    session_handle: " << session_handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    app_id: " << app_id;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    options: " << options;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    zone_set: " << zone_set;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    barriers: ";

    InputCaptureSession *session = qobject_cast<InputCaptureSession *>(Session::getSession(session_handle.path()));

    if (!session) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Tried to set barriers non-existing session " << session_handle.path();
        return 2;
    }

    if (zone_set != 0) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Invalid zone_set " << session_handle.path();
        return 2;
    }

    QList<uint> failedBarriers;

    for (const auto &barrier : barriers) {
        const uint id = barrier.value(u"barrier_id"_s).toUInt();
        int x1, y1, x2, y2;
        const auto position = barrier.value(u"position"_s).value<QDBusArgument>();
        position.beginStructure();
        // (iiii)
        position >> x1 >> y1 >> x2 >> y2;
        position.endStructure();
        qCDebug(XdgDesktopPortalKdeInputCapture) << "        " << id << x1 << y1 << x2 << y2;

        if (id == 0) {
            qCWarning(XdgDesktopPortalKdeInputCapture) << "Invalid barrier id " << id;
            failedBarriers.append(id);
            continue;
        }
        if (x1 != x2 && y1 != y2) {
            qCWarning(XdgDesktopPortalKdeInputCapture) << "Disallowed Diagonal barrier " << id;
            failedBarriers.append(id);
            continue;
        }

        if (!checkBarrier(x1, y1, x2, y2, id)) {
            failedBarriers.append(id);
        } else {
            session->addBarrier(x1, y1, x2, y1);
        }
    }
    results.insert(u"failed_barriers"_s, QVariant::fromValue(failedBarriers));
    return 0;
}

QDBusUnixFileDescriptor InputCapturePortal::ConnectToEIS(const QDBusObjectPath &session_handle, const QString &app_id, const QVariantMap &options)
{
    qCDebug(XdgDesktopPortalKdeInputCapture) << "ConnectToEIS called with parameters:";
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    session_handle: " << session_handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    app_id: " << app_id;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    options: " << options;

    InputCaptureSession *session = qobject_cast<InputCaptureSession *>(Session::getSession(session_handle.path()));
    if (!session) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Tried to call ConnectToEis on non-existing session " << session_handle.path();
        return QDBusUnixFileDescriptor();
    }

    if (session->state != State::Disabled) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Tried to call ConnectToEis on enabled session " << session_handle.path();
        return QDBusUnixFileDescriptor();
    }

    auto msg = QDBusMessage::createMethodCall(u"org.kde.KWin"_s, u"/org/kde/KWin/eis"_s, u"org.kde.KWin.eis"_s, u"connectToEis"_s);
    msg.setArguments({static_cast<int>(session->capabilities())});
    QDBusReply<QDBusUnixFileDescriptor> reply = QDBusConnection::sessionBus().call(msg);
    if (!reply.isValid()) {
        dynamic_cast<QDBusContext *>(parent())->sendErrorReply(reply.error().type(), reply.error().message());
    }
    return reply.value();
}

uint InputCapturePortal::Enable(const QDBusObjectPath &session_handle, const QString &app_id, const QVariantMap &options, QVariantMap &results)
{
    Q_UNUSED(results);
    qCDebug(XdgDesktopPortalKdeInputCapture) << "Enable called with parameters:";
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    session_handle: " << session_handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    app_id: " << app_id;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    options: " << options;

    InputCaptureSession *session = qobject_cast<InputCaptureSession *>(Session::getSession(session_handle.path()));
    if (!session) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Tried to call Enable on non-existing session " << session_handle.path();
        return 2;
    }

    if (session->state != State::Disabled) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Session is already enabled" << session_handle.path();
        return 2;
    }

    session->state = State::Enabled;
    /* HACK for testing Q_EMIT */ Q_EMIT Activated(session_handle, {});
    session->state = State::Active;
    return 0;
}

uint InputCapturePortal::Disable(const QDBusObjectPath &session_handle, const QString &app_id, const QVariantMap &options, QVariantMap &results)
{
    Q_UNUSED(results);
    qCDebug(XdgDesktopPortalKdeInputCapture) << "Disable called with parameters:";
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    session_handle: " << session_handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    app_id: " << app_id;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    options: " << options;

    InputCaptureSession *session = qobject_cast<InputCaptureSession *>(Session::getSession(session_handle.path()));
    if (!session) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Tried to call Enable on non-existing session " << session_handle.path();
        return 2;
    }

    if (session->state == State::Disabled) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Session is not enabled" << session_handle.path();
        return 2;
    }

    session->state = State::Disabled;
    /* HACK for testing Q_EMIT */ Q_EMIT Activated(session_handle, {});
    session->state = State::Active;
    return 0;
}

uint InputCapturePortal::Release(const QDBusObjectPath &session_handle, const QString &app_id, const QVariantMap &options, QVariantMap &results)
{
    Q_UNUSED(results);
    qCDebug(XdgDesktopPortalKdeInputCapture) << "Release called with parameters:";
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    session_handle: " << session_handle.path();
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    app_id: " << app_id;
    qCDebug(XdgDesktopPortalKdeInputCapture) << "    options: " << options;

    InputCaptureSession *session = qobject_cast<InputCaptureSession *>(Session::getSession(session_handle.path()));
    if (!session) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Tried to call Enable on non-existing session " << session_handle.path();
        return 2;
    }

    if (session->state != State::Active) {
        qCWarning(XdgDesktopPortalKdeInputCapture) << "Session is not enabled" << session_handle.path();
        return 2;
    }

    session->state = State::Disabled;
    QPointF cursorPosition = options.value("cursor_position").value<QPointF>(); // (dd)
    /* HACK for testing Q_EMIT */ Q_EMIT Activated(session_handle, {});
    session->state = State::Active;
    return 0;
}
