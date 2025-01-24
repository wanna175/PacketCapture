#include "DetailsDialog.h"

inline DetailsDialog::DetailsDialog(wxWindow* parent, const PacketInfo& packet)
    : wxDialog(parent, wxID_ANY, "��Ŷ �� ����", wxDefaultPosition, wxSize(500, 400)) {
    wxBoxSizer* sizer = new wxBoxSizer(wxVERTICAL);
    SetBackgroundColour(wxColour(240, 240, 240));

    // ��뽺���̽� ��Ʈ�� �� ���� ǥ��
    wxTextCtrl* detailsText = new wxTextCtrl(this, wxID_ANY,
        wxString::FromUTF8(packet.details),
        wxDefaultPosition, wxDefaultSize,
        wxTE_MULTILINE | wxTE_READONLY | wxBORDER_SIMPLE);

    detailsText->SetBackgroundColour(wxColour(255, 255, 255));
    detailsText->SetDefaultStyle(
        wxTextAttr(wxColour(0, 0, 0), wxColour(255, 255, 255),
            wxFont(10, wxFONTFAMILY_TELETYPE, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL))
    );

    sizer->Add(detailsText, 1, wxEXPAND | wxALL, 15);

    wxButton* closeButton = new wxButton(this, wxID_OK, "�ݱ�", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);
    closeButton->SetBackgroundColour(wxColour(52, 152, 219));
    closeButton->SetForegroundColour(*wxWHITE);
    sizer->Add(closeButton, 0, wxALIGN_CENTER | wxALL, 10);

    SetSizerAndFit(sizer);
}
