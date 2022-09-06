package com.Pill.Popper.dao.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.LocalTime;

@Entity
@Table(name = "medicines")
public class Medicine {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    long id;
    @Column(name = "medName", nullable = false)
    String medName;
    @Column(name = "isSyrup")
    String isSyrup;
    @Column(name = "MorningDosage")
    String MorningDosage;
    @Column(name = "AfternoonDosage")
    String AfternoonDosage;
    @Column(name = "EveningDosage")
    String EveningDosage;
    @Column(name = "NightDosage")
    String NightDosage;
    @Column(name = "Morningtime")
    LocalTime MorningTiming ;
    @Column(name = "Afternoontime")
    LocalTime AfternoonTiming ;
    @Column(name = "Eveningtime")
    LocalTime EveningTiming ;
    @Column(name = "Nighttime")
    LocalTime NightTiming ;
    @Column(name="Duration")
    int duration;

    public Medicine() {
        super();

    }



    public Medicine(String medName, String isSyrup, String morningDosage, String afternoonDosage, String eveningDosage,
                    String nightDosage, LocalTime morningTiming, LocalTime afternoonTiming, LocalTime eveningTiming, LocalTime nightTiming, int duration) {
        super();
        this.medName = medName;
        this.isSyrup = isSyrup;
        this.MorningDosage = morningDosage;
        this.AfternoonDosage = afternoonDosage;
        this.EveningDosage = eveningDosage;
        this.NightDosage = nightDosage;
        this.MorningTiming = morningTiming;
        this.AfternoonTiming = afternoonTiming;
        this.EveningTiming = eveningTiming;
        this.NightTiming = nightTiming;
        this.duration=duration;
    }



    public int getDuration() {
        return duration;
    }



    public void setDuration(int duration) {
        this.duration = duration;
    }



    public LocalTime getMorningTiming() {
        return MorningTiming;
    }



    public void setMorningTiming(LocalTime morningTiming) {
        MorningTiming = morningTiming;
    }



    public LocalTime getAfternoonTiming() {
        return AfternoonTiming;
    }



    public void setAfternoonTiming(LocalTime afternoonTiming) {
        AfternoonTiming = afternoonTiming;
    }



    public LocalTime getEveningTiming() {
        return EveningTiming;
    }



    public void setEveningTiming(LocalTime eveningTiming) {
        EveningTiming = eveningTiming;
    }



    public LocalTime getNightTiming() {
        return NightTiming;
    }

    public void setNightTiming(LocalTime nightTiming) {
        NightTiming = nightTiming;
    }



    public String getIsSyrup() {
        return isSyrup;
    }


    public void setIsSyrup(String isSyrup) {
        this.isSyrup = isSyrup;
    }


    public String getMorningDosage() {
        return MorningDosage;
    }


    public void setMorningDosage(String morningDosage) {
        MorningDosage = morningDosage;
    }


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getMedName() {
        return medName;
    }

    public void setMedName(String medName) {
        this.medName = medName;
    }


    public String getMorningdosage() {
        return MorningDosage;
    }

    public void setMorningdosage(String morningdosage) {
        MorningDosage = morningdosage;
    }

    public String getAfternoonDosage() {
        return AfternoonDosage;
    }

    public void setAfternoonDosage(String afternoonDosage) {
        AfternoonDosage = afternoonDosage;
    }

    public String getEveningDosage() {
        return EveningDosage;
    }

    public void setEveningDosage(String eveningDosage) {
        EveningDosage = eveningDosage;
    }

    public String getNightDosage() {
        return NightDosage;
    }

    public void setNightDosage(String nightDosage) {
        NightDosage = nightDosage;
    }

}