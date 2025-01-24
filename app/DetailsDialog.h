#pragma once
#include<wx/wx.h>
#include <wx/textctrl.h>

struct PacketInfo {
    std::string summary;
    std::string details;
};
class DetailsDialog : public wxDialog {
public:
    DetailsDialog(wxWindow* parent, const PacketInfo& packet);
};

