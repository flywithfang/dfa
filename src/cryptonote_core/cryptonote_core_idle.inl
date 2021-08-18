//-----------------------------------------------------------------------------------------------
  double factorial(unsigned int n)
  {
    if (n <= 1)
      return 1.0;
    double f = n;
    while (n-- > 1)
      f *= n;
    return f;
  }
  //-----------------------------------------------------------------------------------------------
  static double probability1(unsigned int blocks, unsigned int expected)
  {
    // https://www.umass.edu/wsp/resources/poisson/#computing
    return pow(expected, blocks) / (factorial(blocks) * exp(expected));
  }
  //-----------------------------------------------------------------------------------------------
  static double probability(unsigned int blocks, unsigned int expected)
  {
    double p = 0.0;
    if (blocks <= expected)
    {
      for (unsigned int b = 0; b <= blocks; ++b)
        p += probability1(b, expected);
    }
    else if (blocks > expected)
    {
      for (unsigned int b = blocks; b <= expected * 3 /* close enough */; ++b)
        p += probability1(b, expected);
    }
    return p;
  }
 

  //-----------------------------------------------------------------------------------------------
  bool core::on_idle()
  {
    if(!m_starter_message_showed)
    {
      std::string main_message;
      if (m_offline)
        main_message = "The daemon is running offline and will not attempt to sync to the Monero network.";
      else
        main_message = "The daemon will start synchronizing with the network. This may take a long time to complete.";
      MGINFO_YELLOW(ENDL << "**********************************************************************" << ENDL
        << main_message << ENDL
        << ENDL
        << "You can set the level of process detailization through \"set_log <level|categories>\" command," << ENDL
        << "where <level> is between 0 (no details) and 4 (very verbose), or custom category based levels (eg, *:WARNING)." << ENDL
        << ENDL
        << "Use the \"help\" command to see the list of available commands." << ENDL
        << "Use \"help <command>\" to see a command's documentation." << ENDL
        << "**********************************************************************" << ENDL);
      m_starter_message_showed = true;
    }

   
    m_block_rate_interval.do_call(boost::bind(&core::check_block_rate, this));
    m_check_updates_interval.do_call(boost::bind(&core::check_updates, this));
    m_check_disk_space_interval.do_call(boost::bind(&core::check_disk_space, this));

    m_blockchain_pruning_interval.do_call(boost::bind(&core::update_blockchain_pruning, this));
    m_mempool.on_idle();
    return true;
  }

 

  //-----------------------------------------------------------------------------------------------
  bool core::check_updates()
  {
    static const char software[] = "dfad";
#ifdef BUILD_TAG
    static const char buildtag[] = BOOST_PP_STRINGIZE(BUILD_TAG);
    static const char subdir[] = "cli"; // because it can never be simple
#else
    static const char buildtag[] = "source";
    static const char subdir[] = "source"; // because it can never be simple
#endif

    if (m_offline)
      return true;

    if (check_updates_level == UPDATES_DISABLED)
      return true;

    std::string version, hash;
    MCDEBUG("updates", "Checking for a new " << software << " version for " << buildtag);
    if (!tools::check_updates(software, buildtag, version, hash))
      return false;

    if (tools::vercmp(version.c_str(), MONERO_VERSION) <= 0)
    {
      m_update_available = false;
      return true;
    }

    std::string url = tools::get_update_url(software, subdir, buildtag, version, true);
    MCLOG_CYAN(el::Level::Info, "global", "Version " << version << " of " << software << " for " << buildtag << " is available: " << url << ", SHA256 hash " << hash);
    m_update_available = true;

    if (check_updates_level == UPDATES_NOTIFY)
      return true;

    url = tools::get_update_url(software, subdir, buildtag, version, false);
    std::string filename;
    const char *slash = strrchr(url.c_str(), '/');
    if (slash)
      filename = slash + 1;
    else
      filename = std::string(software) + "-update-" + version;
    boost::filesystem::path path(epee::string_tools::get_current_module_folder());
    path /= filename;

    boost::unique_lock<boost::mutex> lock(m_update_mutex);

    if (m_update_download != 0)
    {
      MCDEBUG("updates", "Already downloading update");
      return true;
    }

    crypto::hash file_hash;
    if (!tools::sha256sum(path.string(), file_hash) || (hash != epee::string_tools::pod_to_hex(file_hash)))
    {
      MCDEBUG("updates", "We don't have that file already, downloading");
      const std::string tmppath = path.string() + ".tmp";
      if (epee::file_io_utils::is_file_exist(tmppath))
      {
        MCDEBUG("updates", "We have part of the file already, resuming download");
      }
      m_last_update_length = 0;
      m_update_download = tools::download_async(tmppath, url, [this, hash, path](const std::string &tmppath, const std::string &uri, bool success) {
        bool remove = false, good = true;
        if (success)
        {
          crypto::hash file_hash;
          if (!tools::sha256sum(tmppath, file_hash))
          {
            MCERROR("updates", "Failed to hash " << tmppath);
            remove = true;
            good = false;
          }
          else if (hash != epee::string_tools::pod_to_hex(file_hash))
          {
            MCERROR("updates", "Download from " << uri << " does not match the expected hash");
            remove = true;
            good = false;
          }
        }
        else
        {
          MCERROR("updates", "Failed to download " << uri);
          good = false;
        }
        boost::unique_lock<boost::mutex> lock(m_update_mutex);
        m_update_download = 0;
        if (success && !remove)
        {
          std::error_code e = tools::replace_file(tmppath, path.string());
          if (e)
          {
            MCERROR("updates", "Failed to rename downloaded file");
            good = false;
          }
        }
        else if (remove)
        {
          if (!boost::filesystem::remove(tmppath))
          {
            MCERROR("updates", "Failed to remove invalid downloaded file");
            good = false;
          }
        }
        if (good)
          MCLOG_CYAN(el::Level::Info, "updates", "New version downloaded to " << path.string());
      }, [this](const std::string &path, const std::string &uri, size_t length, ssize_t content_length) {
        if (length >= m_last_update_length + 1024 * 1024 * 10)
        {
          m_last_update_length = length;
          MCDEBUG("updates", "Downloaded " << length << "/" << (content_length ? std::to_string(content_length) : "unknown"));
        }
        return true;
      });
    }
    else
    {
      MCDEBUG("updates", "We already have " << path << " with expected hash");
    }

    lock.unlock();

    if (check_updates_level == UPDATES_DOWNLOAD)
      return true;

    MCERROR("updates", "Download/update not implemented yet");
    return true;
  }

   //-----------------------------------------------------------------------------------------------
  bool core::check_block_rate()
  {
    if (m_offline || m_nettype == FAKECHAIN || m_target_blockchain_height > get_current_blockchain_height() || m_target_blockchain_height == 0)
    {
      MDEBUG("Not checking block rate, offline or syncing");
      return true;
    }

    static constexpr double threshold = 1. / (864000 / DIFFICULTY_TARGET); // one false positive every 10 days
    static constexpr unsigned int max_blocks_checked = 150;

    const time_t now = time(NULL);
    const std::vector<time_t> timestamps = m_blockchain.get_last_block_timestamps(max_blocks_checked);

    static const unsigned int seconds[] = { 5400, 3600, 1800, 1200, 600 };
    for (size_t n = 0; n < sizeof(seconds)/sizeof(seconds[0]); ++n)
    {
      unsigned int b = 0;
      const time_t time_boundary = now - static_cast<time_t>(seconds[n]);
      for (time_t ts: timestamps) b += ts >= time_boundary;
      const double p = probability(b, seconds[n] / DIFFICULTY_TARGET);
      MDEBUG("blocks in the last " << seconds[n] / 60 << " minutes: " << b << " (probability " << p << ")");
      if (p < threshold)
      {
        MWARNING("There were " << b << (b == max_blocks_checked ? " or more" : "") << " blocks in the last " << seconds[n] / 60 << " minutes, there might be large hash rate changes, or we might be partitioned, cut off from the Monero network or under attack, or your computer's time is off. Or it could be just sheer bad luck.");

        std::shared_ptr<tools::Notify> block_rate_notify = m_block_rate_notify;
        if (block_rate_notify)
        {
          auto expected = seconds[n] / DIFFICULTY_TARGET;
          block_rate_notify->notify("%t", std::to_string(seconds[n] / 60).c_str(), "%b", std::to_string(b).c_str(), "%e", std::to_string(expected).c_str(), NULL);
        }

        break; // no need to look further
      }
    }

    return true;
  }

  
  //-----------------------------------------------------------------------------------------------
  bool core::check_disk_space()
  {
    uint64_t free_space = get_free_space();
    if (free_space < 1ull * 1024 * 1024 * 1024) // 1 GB
    {
      const el::Level level = el::Level::Warning;
      MCLOG_RED(level, "global", "Free space is below 1 GB on " << m_config_folder);
    }
    return true;
  }


   //-----------------------------------------------------------------------------------------------
  bool core::update_blockchain_pruning()
  {
    return m_blockchain.update_blockchain_pruning();
  }