#include <wx/wx.h>
#include "MainFrame.h"

// wxApp ±¸Çö
class PacketCaptureApp : public wxApp {
public:
    virtual bool OnInit() override {
        MainFrame* frame = new MainFrame("Packet Capture Tool");
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(PacketCaptureApp);