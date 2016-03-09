/*
 * Copyright (C) 2012-2014 Arctium Emulation <http://arctium.org>
 * Copyright (C) 2008-2016 TrinityCore <http://www.trinitycore.org/>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "Helper.hpp"
#include "Patcher.hpp"
#include "Patches/Common.hpp"
#include "Patches/Mac.hpp"
#include "Patches/Windows.hpp"
#include "Patterns/Common.hpp"
#include "Patterns/Mac.hpp"
#include "Patterns/Windows.hpp"

#include <CompilerDefs.h>

#include <boost/algorithm/string/replace.hpp>
#include <boost/program_options.hpp>

#if PLATFORM == PLATFORM_WINDOWS
#include <Shlobj.h>
#elif PLATFORM == PLATFORM_UNIX
#include <pwd.h>
#endif

namespace po = boost::program_options;

namespace Connection_Patcher
{
    po::variables_map GetConsoleArguments(int argc, char** argv);

    namespace
    {
        template<typename PATCH, typename PATTERN>
        void do_module(const std::string& moduleName, const boost::filesystem::path& path)
        {
            boost::filesystem::path const modulePath
                (path / std::string(&moduleName[0], 2) / std::string(&moduleName[2], 2));
            boost::filesystem::path const module(modulePath / moduleName);

            if (!boost::filesystem::exists(module))
            {
                std::cout << "Base module doesn't exist, downloading it...\n";

                if (!boost::filesystem::exists(modulePath))
                    boost::filesystem::create_directories(modulePath);

                std::ofstream outFile(module.string(), std::ofstream::out | std::ofstream::binary);
                Helper::DownloadFile("xx.depot.battle.net", 1119, "/" + moduleName, outFile);
                outFile.close();
                std::cout << "Done.\n";
            }
        }

        template<typename PATCH, typename PATTERN>
        void do_patches(Patcher* patcher, boost::filesystem::path output, bool patchVersionPath, uint32_t buildNumber)
        {
            std::cout << "patching Portal\n";
            // '.actual.battle.net' -> '' to allow for set portal 'host'
            patcher->Patch(Patches::Common::Portal(), Patterns::Common::Portal());

            std::cout << "patching redirect RSA Modulus\n";
            // public component of connection signing key to use known key pair
            patcher->Patch(Patches::Common::Modulus(), Patterns::Common::Modulus());

            std::cout << "patching BNet certificate file location\n";
            // replace name of the file with certificates
            patcher->Patch(Patches::Common::CertFileName(), Patterns::Common::CertFileName());

            std::cout << "patching BNet certificate file to load from local path instead of CASC\n";
            // force loading tc_bundle.txt from local directory instead of CASC
            patcher->Patch(PATCH::CertBundleCASCLocalFile(), PATTERN::CertBundleCASCLocalFile());

            std::cout << "patching BNet certificate file signature check\n";
            // remove signature check from certificate bundle
            patcher->Patch(PATCH::CertBundleSignatureCheck(), PATTERN::CertBundleSignatureCheck());

            if (patchVersionPath)
            {
                std::cout << "patching Versions\n";
                // sever the connection to blizzard's versions file to stop it from updating and replace with custom version
                // hardcode %s.patch.battle.net:1119/%s/versions to trinity6.github.io/%s/%s/build/versi
                std::string verPatch(Patches::Common::VersionsFile());
                std::string buildPattern = "build";

                boost::algorithm::replace_all(verPatch, buildPattern, std::to_string(buildNumber));
                std::vector<unsigned char> verVec(verPatch.begin(), verPatch.end());
                patcher->Patch(verVec, Patterns::Common::VersionsFile());
            }

            patcher->Finish(output);

            std::cout << "Patching done.\n";
        }
    }

    po::variables_map GetConsoleArguments(int argc, char** argv)
    {
        po::options_description all("Allowed options");
        all.add_options()
            ("help,h", "print usage message")
            ("path", po::value<std::string>()->required(), "Path to the Wow.exe")
            ("extra,e", po::value<uint32_t>()->implicit_value(0), "Enable patching of versions file download path. Version can be specified explicitly.")
            ;

        po::positional_options_description pos;
        pos.add("path", 1);

        po::variables_map vm;
        try
        {
            po::store(po::command_line_parser(argc, argv).options(all).positional(pos).run(), vm);
            po::notify(vm);
        }
        catch (std::exception& e)
        {
            std::cerr << e.what() << "\n";
        }

        if (vm.count("help"))
            std::cout << all << "\n";

        if (!vm.count("path"))
            throw std::invalid_argument("Wrong number of arguments: Missing client file.");

        return vm;
    }
}

int main(int argc, char** argv)
{
    using namespace Connection_Patcher;

    try
    {
        bool patchVersionPath = false;
        int wowBuild = 0;

        auto vm = GetConsoleArguments(argc, argv);

        // exit if help is enabled
        if (vm.count("help"))
        {
            std::cin.get();
            return 0;
        }

        std::string const binary_path(std::move(vm["path"].as<std::string>()));
        std::string renamed_binary_path(binary_path);

        boost::filesystem::copy_file(boost::filesystem::system_complete(argv[0]).remove_filename() / "tc_bundle.txt",
            boost::filesystem::path(binary_path).remove_filename() / "tc_bundle.txt",
            boost::filesystem::copy_option::overwrite_if_exists);

        std::cout << "Creating patched binary..." << std::endl;

        Patcher patcher(binary_path);

        if (vm.count("extra"))
        {
            patchVersionPath = true;
            wowBuild = vm["extra"].as<uint32_t>();

            if (wowBuild == 0)
                wowBuild = Helper::GetBuildNumber(patcher.GetBinary());

            if (wowBuild == 0 || wowBuild < 10000 || wowBuild > 65535) // Build number has to be exactly 5 characters long
                throw std::runtime_error("Could not retrieve build number or it was out of range. Build: " + std::to_string(wowBuild));

            std::cout << "Determined build number: " << std::to_string(wowBuild) << std::endl;
        }

        switch (patcher.GetType())
        {
            case Constants::BinaryTypes::Pe32:
                std::cout << "Win32 client...\n";

                boost::algorithm::replace_all(renamed_binary_path, ".exe", "_Patched.exe");
                do_patches<Patches::Windows::x86, Patterns::Windows::x86>
                    (&patcher, renamed_binary_path, patchVersionPath, wowBuild);
                break;
            case Constants::BinaryTypes::Pe64:
                std::cout << "Win64 client...\n";

                boost::algorithm::replace_all(renamed_binary_path, ".exe", "_Patched.exe");
                do_patches<Patches::Windows::x64, Patterns::Windows::x64>
                    (&patcher, renamed_binary_path, patchVersionPath, wowBuild);
                break;
            case Constants::BinaryTypes::Mach64:
                std::cout << "Mac client...\n";

                boost::algorithm::replace_all(renamed_binary_path, ".app", " Patched.app");
                Helper::CopyDir(boost::filesystem::path(binary_path).parent_path()/*MacOS*/.parent_path()/*Contents*/.parent_path()
                        , boost::filesystem::path(renamed_binary_path).parent_path()/*MacOS*/.parent_path()/*Contents*/.parent_path()
                        );

                do_patches<Patches::Mac::x64, Patterns::Mac::x64>
                    (&patcher, renamed_binary_path, patchVersionPath, wowBuild);

                {
                    namespace fs = boost::filesystem;
                    fs::permissions(renamed_binary_path, fs::add_perms | fs::others_exe | fs::group_exe | fs::owner_exe);
                }
                break;
            default:
                throw std::runtime_error("Type: " + std::to_string(static_cast<uint32_t>(patcher.GetType())) + " not supported!");
        }

        std::cout << "Successfully created your patched binaries.\n";

        return 0;
    }
    catch (std::exception const& ex)
    {
        std::cerr << "EX: " << ex.what() << std::endl;
        std::cerr << "An error occurred. Press ENTER to continue...";
        std::cin.get();
        return 1;
    }
}
