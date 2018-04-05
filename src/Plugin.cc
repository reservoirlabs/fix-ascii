// Copyright 2018 Reservoir Labs

#include "plugin/Plugin.h"

#include "FIX.h"

namespace plugin {
namespace Bro_FIX4_FIXT {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("FIX4_FIXT",
		             ::analyzer::FIX4_FIXT::FIX_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "Bro::FIX4_FIXT";
		config.description = "Financial Information eXchange analyzer for FIX 4.x and FIXT";
                config.version.major = 1;
                config.version.minor = 0;
		return config;
		}
} plugin;

}
}
