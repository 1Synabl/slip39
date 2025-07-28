#include "include/slip39_dart/slip39_dart_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "slip39_dart_plugin.h"

void Slip39DartPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  slip39_dart::Slip39DartPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
