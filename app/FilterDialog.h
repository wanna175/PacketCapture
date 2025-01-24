#pragma once
#include <wx/wx.h>

class FilterDialog : public wxDialog {
public:
    FilterDialog(wxWindow* parent);

    wxString GetFilter() const;

private:
    wxTextCtrl* filterInput;
};

