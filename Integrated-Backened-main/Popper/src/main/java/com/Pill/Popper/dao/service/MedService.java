package com.Pill.Popper.dao.service;

import java.util.List;

import com.Pill.Popper.dao.entity.Medicine;


public interface MedService {
    Medicine saveMed(Medicine medicine);
    List<Medicine> getAllMedicines();
    Medicine getMedById(long id);
    Medicine updateMed(Medicine medicine, long id);
    void deleteMed(long id);
    String getAllMedicinesAlarm();
}