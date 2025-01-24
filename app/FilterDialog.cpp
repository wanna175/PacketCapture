#include "FilterDialog.h"

inline FilterDialog::FilterDialog(wxWindow* parent) : wxDialog(parent, wxID_ANY, "���� ����", wxDefaultPosition, wxSize(400, 200)) {
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
    SetBackgroundColour(wxColour(240, 240, 240)); // ���� ȸ�� ���

    // ���� �Է� �ʵ� (����� ��Ÿ��)
    wxStaticText* label = new wxStaticText(this, wxID_ANY, "���� �Է� (��: IP, ��Ʈ):");
    label->SetForegroundColour(wxColour(50, 50, 50));

    filterInput = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxDefaultSize,
        wxBORDER_SIMPLE); // ����ȭ�� �׵θ�
    filterInput->SetBackgroundColour(wxColour(255, 255, 255));
    filterInput->SetForegroundColour(wxColour(0, 0, 0));

    mainSizer->Add(label, 0, wxLEFT | wxRIGHT | wxTOP, 15);
    mainSizer->Add(filterInput, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 15);

    // �������� ��ư ������
    wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
    wxButton* okButton = new wxButton(this, wxID_OK, "����", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);
    wxButton* cancelButton = new wxButton(this, wxID_CANCEL, "���", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);

    // ��ư ���� �� ��Ÿ�� ����
    okButton->SetBackgroundColour(wxColour(52, 152, 219)); // �Ķ���
    okButton->SetForegroundColour(*wxWHITE);
    cancelButton->SetBackgroundColour(wxColour(231, 76, 60)); // ������
    cancelButton->SetForegroundColour(*wxWHITE);

    buttonSizer->Add(okButton, 1, wxEXPAND | wxALL, 5);
    buttonSizer->Add(cancelButton, 1, wxEXPAND | wxALL, 5);

    mainSizer->Add(buttonSizer, 0, wxALIGN_CENTER);

    SetSizerAndFit(mainSizer);
}

inline wxString FilterDialog::GetFilter() const {
    return filterInput->GetValue();
}
