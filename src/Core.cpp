/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 athre0z
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "Core.hpp"

#include "Config.hpp"
#include "Settings.hpp"
#include "Ui.hpp"
#include "ImportExport.hpp"
#include "RETypedef.hpp"

#include <QDir>
#include <QApplication>
#include <QMessageBox>
#include <idp.hpp>
#include <name.hpp>
#include <diskio.hpp>
#include <loader.hpp>

// =============================================================================================== //
// [Core]                                                                                          //
// =============================================================================================== //

Core::Core()
    : m_originalMangler(nullptr)
{
#if IDA_SDK_VERSION >= 670
    static const action_desc_t action = 
    {
        sizeof(action),
        "retypedef_open_name_subst_editor",
        "Edit name substitutions...",
        &m_optionsMenuItemClickedAction,
        &PLUGIN
    };

    register_action(action);
    attach_action_to_menu("Options/", "retypedef_open_name_subst_editor", 0);
#else
    add_menu_item("Options/", "Edit name substitutions...", nullptr, 0, 
        &Core::onOptionsMenuItemClicked, this);
#endif

    // First start? Initialize with default rules.
    Settings settings;
    if (settings.value(Settings::kFirstStart, true).toBool())
    {
        QSettings defaultRules(":/Misc/default_rules.ini", QSettings::IniFormat);
        SettingsImporterExporter importer(&m_substitutionManager, &defaultRules);
        importer.importRules();
        saveToSettings();
        settings.setValue(Settings::kFirstStart, false);
    }

    // Load rules from settings and subscribe to changes in the manager
    try
    {
        SettingsImporterExporter importer(&m_substitutionManager, &settings);
        importer.importRules();
    }
    catch (const SettingsImporterExporter::Error& e)
    {
        msg("[" PLUGIN_NAME "] Cannot load settings: %s\n", e.what());
    }
    connect(&m_substitutionManager, SIGNAL(entryAdded()), SLOT(saveToSettings()));
    connect(&m_substitutionManager, SIGNAL(entryDeleted()), SLOT(saveToSettings()));

    hook_to_notification_point(HT_IDP, &Core::IDP_Hook);
}

Core::~Core()
{
    // Remove demangler detour
    unhook_from_notification_point(HT_IDP, &Core::IDP_Hook);

#if IDA_SDK_VERSION >= 670
    detach_action_from_menu("Options/", "retypedef_open_name_subst_editor");
    unregister_action("retypedef_open_name_subst_editor");
#else
    del_menu_item("Options/Edit name substitutions...");
#endif
}

#if IDA_SDK_VERSION >= 670
int Core::OptionsMenuItemClickedAction::activate(action_activation_ctx_t * /*ctx*/)
{
    onOptionsMenuItemClicked(&Core::instance());
    return 1;
}

action_state_t Core::OptionsMenuItemClickedAction::update(action_update_ctx_t * /*ctx*/)
{
    return AST_ENABLE_ALWAYS;
}
#endif

void Core::runPlugin()
{
    AboutDialog().exec();
}

ssize_t idaapi Core::IDP_Hook(void* user_data, int notification_code, va_list va) {
    switch (notification_code) {
    case ::processor_t::ev_demangle_name:
        int32_t *res = va_arg(va, int32_t *);
        qstring *out = va_arg(va, qstring *);
        const char* name = va_arg(va, const char *);
        uint32 disable_mask = va_arg(va, uint32);
        int32 demreq = va_arg(va, int32);
        unhook_from_notification_point(HT_IDP, &Core::IDP_Hook);
        
        auto _res = demangle_name(out, name, disable_mask, (demreq_type_t)demreq);
        int ret = 0;
        if (_res < ME_NOERROR_LIMIT || _res >= 0) {
            auto& thiz = instance();
            thiz.m_substitutionManager.applyToString(out);
            ret = 1;
            *res = _res;
        }

        hook_to_notification_point(HT_IDP, &Core::IDP_Hook);
        return ret;
    }
    return 0;
}

bool Core::onOptionsMenuItemClicked(void* userData)
{
    auto thiz = reinterpret_cast<Core*>(userData);
    SubstitutionModel model(&thiz->m_substitutionManager);
    SubstitutionEditor editor(qApp->activeWindow());
    editor.setModel(&model);

    editor.exec();
    return 0;
}

void Core::saveToSettings()
{
    try
    {
        Settings settings;
        SettingsImporterExporter exporter(&m_substitutionManager, &settings);
        exporter.exportRules();

        request_refresh(IWID_NAMES | IWID_DISASMS);
    }
    catch (const SettingsImporterExporter::Error &e)
    {
        msg("[" PLUGIN_NAME "] Cannot save to settings: %s\n", e.what());
    }
}

// ============================================================================================== //
