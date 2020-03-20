#include <Windows.h>
#include <Psapi.h>

#include "hunt/hunts/HuntT1055.h"
#include "util/eventlogs/EventLogs.h"
#include "util/log/Log.h"
#include "util/log/HuntLogMessage.h"
#include "common/StringUtils.h"

#include "pe_sieve.h"
#include "pe_sieve_api.h"

namespace Hunts{

	HuntT1055::HuntT1055() : Hunt(L"T1055 - Process Injection") {
		dwSupportedScans = (DWORD) Aggressiveness::Normal;
		dwCategoriesAffected = (DWORD) Category::Processes;
		dwSourcesInvolved = (DWORD) DataSource::Processes;
		dwTacticsUsed = (DWORD) Tactic::PrivilegeEscalation | (DWORD) Tactic::DefenseEvasion;
	}

	bool ScanProcess(DWORD pid, Reaction& reaction){
		pesieve::t_params params = {
			pid,
			3,
			pesieve::PE_IMPREC_NONE,
			true,
			pesieve::OUT_NO_DIR,
			true,
			false,
			false,
			false,
			pesieve::PE_DUMP_AUTO,
			false,
			0
		};

		WRAP(ProcessScanReport*, report, scan_process(params), delete data);

		auto summary = report->generateSummary();
		if(summary.errors){
			LOG_WARNING("Unable to scan process " << pid << " due to an error in PE-Sieve.dll");
		}
		
		if(summary.skipped){
			LOG_WARNING("Skipped scanning " << summary.skipped << " modules in process " << pid << ". This is likely due to use of .NET");
		}

		if(summary.suspicious && !summary.errors){
			DWORD identifiers = 0;
			if(summary.replaced) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Replaced);
			if(summary.hdr_mod) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::HeaderModified);
			if(summary.detached) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Detached);
			if(summary.hooked) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Hooked);
			if(summary.implanted) identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Implanted);
			if(summary.implanted + summary.hooked + summary.detached + summary.hdr_mod + summary.replaced != summary.suspicious)
				identifiers |= static_cast<DWORD>(ProcessDetectionMethod::Other);

			std::wstring path = StringToWidestring(report->mainImagePath);

			for(auto module : report->module_reports){
				if(module->status & ProcessScanReport::REPORT_SUSPICIOUS){
					reaction.ProcessIdentified(std::make_shared<PROCESS_DETECTION>(path, std::wstring{}, pid, module->module, module->moduleSize, identifiers));
				}
			}

			return true;
		}

		return false;
	}

	int HuntT1055::ScanNormal(const Scope& scope, Reaction reaction){
		LOG_INFO(L"Hunting for T1055 " << name << L" at level Normal");
		reaction.BeginHunt(GET_INFO());

		int identified = 0;

		DWORD processes[1024];
		DWORD ProcessCount = 0;
		ZeroMemory(processes, sizeof(processes));
		auto success = EnumProcesses(processes, sizeof(processes), &ProcessCount);
		if(success){
			ProcessCount /= sizeof(DWORD);
			for(int i = 0; i < ProcessCount; i++){
				if(scope.ProcessIsInScope(processes[i])){
					if(ScanProcess(processes[i], reaction)){
						identified++;
					}
				}
			}
		} else {
			LOG_ERROR("Unable to enumerate processes - Process related hunts will not run.");
		}

		reaction.EndHunt();
		return identified;
	}

}