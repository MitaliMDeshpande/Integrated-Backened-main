package com.Pill.Popper.dao.service;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.*;
import java.util.List;

import com.Pill.Popper.dao.entity.Medicine;
import com.Pill.Popper.dao.repository.MedicineRepository;
import com.Pill.Popper.exception.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;



@Service
public class MedServiceImpl implements MedService{
    @Autowired
    MedicineRepository medRepo;

    public MedServiceImpl(MedicineRepository medRepo) {
        super();
        this.medRepo = medRepo;
    }

    @Override
    public Medicine saveMed(Medicine medicine) {
        // TODO Auto-generated method stub

        return medRepo.save(medicine);
    }

    @Override
    public List<Medicine> getAllMedicines() {
        // TODO Auto-generated method stub
        return medRepo.findAll();
    }

    @Override
    public Medicine getMedById(long id) {
        Optional<Medicine> med = medRepo.findById(id);
        if(med.isPresent()) {
            return med.get();
        }else {
            throw new ResourceNotFoundException("Medicine", "Id", id);
        }
    }

    @Override
    public Medicine updateMed(Medicine medicine, long id) {
        Optional<Medicine> med = medRepo.findById(id);
        if(med.isPresent()) {
            Medicine medicine1= med.get();
            medicine1.setMedName(medicine.getMedName());
            medicine1.setMorningdosage(medicine.getMorningdosage());
            medicine1.setAfternoonDosage(medicine.getEveningDosage());
            medicine1.setEveningDosage(medicine.getEveningDosage());
            medicine1.setNightDosage(medicine.getNightDosage());
            medicine1.setMorningTiming(medicine.getMorningTiming());
            medicine1.setAfternoonTiming(medicine.getAfternoonTiming());
            medicine1.setEveningTiming(medicine.getEveningTiming());
            medicine1.setNightTiming(medicine.getNightTiming());
            medicine1.setDuration(medicine.getDuration());
            medRepo.save(medicine1);
            return medicine1;
        }else {
            throw new ResourceNotFoundException("Medicine", "Id", id);
        }

    }

    @Override
    public void deleteMed(long id) {
        Optional<Medicine> med = medRepo.findById(id);
        if(med.isPresent()) {
            medRepo.deleteById(id);
        }else {
            throw new ResourceNotFoundException("Medicine", "Id", id);
        }

    }
    public String getAllMedicinesAlarm() {
        LocalTime now = LocalTime.now();
        LocalDate day=LocalDate.now();
        DayOfWeek dayOfWeek = day.getDayOfWeek();
        int d = dayOfWeek.getValue();
        int lhrs,lmins;
        String meds="";
        int morhrs,mormins, afterhrs, aftermins, evenhrs, evenmins, nighthrs, nightmins;
        lhrs=now.getHour();
        lmins=now.getMinute();
        List<Medicine> med = medRepo.findAll();
        boolean flag=false;
        for(Medicine m:med){
            if(m.getMorningTiming()!=null) {
                LocalTime morningtime=m.getMorningTiming().minusMinutes(30);
                morhrs=morningtime.getHour();
                mormins=morningtime.getMinute();
                if(morhrs==lhrs && lmins==mormins&& d<m.getDuration()){
                    meds=meds+" "+m.getMedName();
                    flag=true;
                }
            }
            if(m.getAfternoonTiming()!=null) {
                LocalTime afternoontime=m.getAfternoonTiming().minusMinutes(30);
                afterhrs=afternoontime.getHour();
                aftermins=afternoontime.getMinute();
                if(afterhrs==lhrs && lmins==aftermins&&d<m.getDuration())
                {
                    meds=meds+" "+m.getMedName();
                    flag=true;
                }
            }
            if(m.getEveningTiming()!=null) {
                LocalTime eveningtime=m.getEveningTiming().minusMinutes(30);
                evenhrs=eveningtime.getHour();
                evenmins=eveningtime.getMinute();
                if(evenhrs==lhrs && evenmins==lmins&&d<m.getDuration())
                {
                    meds=meds+", "+m.getMedName();
                    flag=true;
                }
            }
            if(m.getNightTiming()!=null) {
                LocalTime nighttime=m.getNightTiming().minusMinutes(30);
                nighthrs=nighttime.getHour();
                nightmins=nighttime.getMinute();
                if(nighthrs==lhrs && lmins==nightmins&&d<m.getDuration()) {

                    flag=true;
                }
            }
        }
        if(flag==true)
        {
            return "Time to take your Medicine: "+meds;
        }
        return null;
    }


}