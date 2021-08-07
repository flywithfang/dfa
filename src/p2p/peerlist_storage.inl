class peerlist_storage
  {
  public:
    peerlist_storage()
      : m_types{}
    {}

    //! \return Peers stored in stream `src` in `new_format` (portable archive or older non-portable).
    static boost::optional<peerlist_storage> open(std::istream& src, const bool new_format);

    //! \return Peers stored in file at `path`
    static boost::optional<peerlist_storage> open(const std::string& path);

    peerlist_storage(peerlist_storage&&) = default;
    peerlist_storage(const peerlist_storage&) = delete;

    ~peerlist_storage() noexcept;

    peerlist_storage& operator=(peerlist_storage&&) = default;
    peerlist_storage& operator=(const peerlist_storage&) = delete;

    //! Save peers from `this` and `other` in stream `dest`.
    bool store(std::ostream& dest, const peerlist_types& other) const;

    //! Save peers from `this` and `other` in one file at `path`.
    bool store(const std::string& path, const peerlist_types& other) const;

    //! \return Peers in `zone` and from remove from `this`.
    peerlist_types take_zone();

  private:
    peerlist_types m_types;
  };
