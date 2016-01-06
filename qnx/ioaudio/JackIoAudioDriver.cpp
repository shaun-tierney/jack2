/*
 Copyright (C) 2001 Paul Davis
 Copyright (C) 2004 Grame

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#define __STDC_FORMAT_MACROS   // For inttypes.h to work in C++
#include <iostream>
#include <math.h>
#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <string.h>

#include "JackIoAudioDriver.h"
#include "JackEngineControl.h"
#include "JackClientControl.h"
#include "JackPort.h"
#include "JackGraphManager.h"
#include "JackLockedEngine.h"
#ifdef __ANDROID__
#include "JackAndroidThread.h"
#else
#include "JackPosixThread.h"
#endif
#include "JackCompilerDeps.h"
#include "JackServerGlobals.h"

static struct jack_constraint_enum_str_descriptor midi_constraint_descr_array[] =
    {
      {
        "none",
        "no MIDI driver"
      },
      {
        "seq",
        "io-audio Sequencer driver"
      },
      {
        "raw",
        "io-audio RawMIDI driver"
      },
      {
        0
      }
    };

static struct jack_constraint_enum_char_descriptor dither_constraint_descr_array[] =
    {
      {
        'n',
        "none"
      },
      {
        'r',
        "rectangular"
      },
      {
        's',
        "shaped"
      },
      {
        't',
        "triangular"
      },
      {
        0
      }
    };

namespace Jack
{

    int JackIoAudioDriver::SetBufferSize(
        jack_nframes_t buffer_size )
    {
        jack_log( "JackIoAudioDriver::SetBufferSize %ld",
                  buffer_size );
        int res =
            ioaudio_driver_reset_parameters( (ioaudio_driver_t *)fDriver,
                                             buffer_size,
                                             ( (ioaudio_driver_t *)fDriver )->user_nperiods,
                                             ( (ioaudio_driver_t *)fDriver )->frame_rate );

        if( res == 0 )
            { // update fEngineControl and fGraphManager
            JackAudioDriver::SetBufferSize( buffer_size ); // Generic change, never fails
            // io-audio specific
            UpdateLatencies();
            }
        else
            {
            // Restore old values
            ioaudio_driver_reset_parameters( (ioaudio_driver_t *)fDriver,
                                             fEngineControl->fBufferSize,
                                             ( (ioaudio_driver_t *)fDriver )->user_nperiods,
                                             ( (ioaudio_driver_t *)fDriver )->frame_rate );
            }

        return res;
    }

    void JackIoAudioDriver::UpdateLatencies()
    {
        jack_latency_range_t range;
        ioaudio_driver_t* ioaudio_driver = (ioaudio_driver_t*)fDriver;

        for( int i = 0; i < fCaptureChannels; i++ )
            {
            range.min = range.max = ioaudio_driver->frames_per_cycle
                + ioaudio_driver->capture_frame_latency;
            fGraphManager->GetPort( fCapturePortList[i] )->SetLatencyRange(
                                                                            JackCaptureLatency,
                                                                            &range );
            }

        for( int i = 0; i < fPlaybackChannels; i++ )
            {
            // Add one buffer more latency if "async" mode is used...
            range.min = range.max =
                ( ioaudio_driver->frames_per_cycle
                    * ( ioaudio_driver->user_nperiods - 1 ) )
                    + ( ( fEngineControl->fSyncMode ) ?
                        0 : fEngineControl->fBufferSize )
                    + ioaudio_driver->playback_frame_latency;
            fGraphManager->GetPort( fPlaybackPortList[i] )->SetLatencyRange(
                                                                             JackPlaybackLatency,
                                                                             &range );
            // Monitor port
            if( fWithMonitorPorts )
                {
                range.min = range.max = ioaudio_driver->frames_per_cycle;
                fGraphManager->GetPort( fMonitorPortList[i] )->SetLatencyRange(
                                                                                JackCaptureLatency,
                                                                                &range );
                }
            }
    }

    int JackIoAudioDriver::Attach()
    {
        JackPort* port;
        jack_port_id_t port_index;
        unsigned long port_flags = (unsigned long) CaptureDriverFlags;
        char name[REAL_JACK_PORT_NAME_SIZE];
        char alias[REAL_JACK_PORT_NAME_SIZE];

        assert( fCaptureChannels < DRIVER_PORT_NUM );
        assert( fPlaybackChannels < DRIVER_PORT_NUM );

        ioaudio_driver_t* ioaudio_driver = (ioaudio_driver_t*)fDriver;

        if( ioaudio_driver->has_hw_monitoring )
            port_flags |= JackPortCanMonitor;

        // io-audio driver may have changed the values
        JackAudioDriver::SetBufferSize( ioaudio_driver->frames_per_cycle );
        JackAudioDriver::SetSampleRate( ioaudio_driver->frame_rate );

        jack_log( "JackIoAudioDriver::Attach fBufferSize %ld fSampleRate %ld",
                  fEngineControl->fBufferSize,
                  fEngineControl->fSampleRate );

        for( int i = 0; i < fCaptureChannels; i++ )
            {
            snprintf( alias,
                      sizeof( alias ),
                      "%s:%s:out%d",
                      fAliasName,
                      fCaptureDriverName,
                      i + 1 );
            snprintf( name,
                      sizeof( name ),
                      "%s:capture_%d",
                      fClientControl.fName,
                      i + 1 );
            if( fEngine->PortRegister( fClientControl.fRefNum,
                                       name,
                                       JACK_DEFAULT_AUDIO_TYPE,
                                       (JackPortFlags)port_flags,
                                       fEngineControl->fBufferSize,
                                       &port_index ) < 0 )
                {
                jack_error( "driver: cannot register port for %s",
                            name );
                return -1;
                }
            port = fGraphManager->GetPort( port_index );
            port->SetAlias( alias );
            fCapturePortList[i] = port_index;
            jack_log( "JackIoAudioDriver::Attach fCapturePortList[i] %ld ",
                      port_index );
            }

        port_flags = (unsigned long) PlaybackDriverFlags;

        for( int i = 0; i < fPlaybackChannels; i++ )
            {
            snprintf( alias,
                      sizeof( alias ),
                      "%s:%s:in%d",
                      fAliasName,
                      fPlaybackDriverName,
                      i + 1 );
            snprintf( name,
                      sizeof( name ),
                      "%s:playback_%d",
                      fClientControl.fName,
                      i + 1 );
            if( fEngine->PortRegister( fClientControl.fRefNum,
                                       name,
                                       JACK_DEFAULT_AUDIO_TYPE,
                                       (JackPortFlags)port_flags,
                                       fEngineControl->fBufferSize,
                                       &port_index ) < 0 )
                {
                jack_error( "driver: cannot register port for %s",
                            name );
                return -1;
                }
            port = fGraphManager->GetPort( port_index );
            port->SetAlias( alias );
            fPlaybackPortList[i] = port_index;
            jack_log( "JackIoAudioDriver::Attach fPlaybackPortList[i] %ld ",
                      port_index );

            // Monitor ports
            if( fWithMonitorPorts )
                {
                jack_log( "Create monitor port" );
                snprintf( name,
                          sizeof( name ),
                          "%s:monitor_%d",
                          fClientControl.fName,
                          i + 1 );
                if( fEngine->PortRegister( fClientControl.fRefNum,
                                           name,
                                           JACK_DEFAULT_AUDIO_TYPE,
                                           MonitorDriverFlags, fEngineControl->fBufferSize, &port_index) <0 )
                    {
                    jack_error("io-audio: cannot register monitor port for %s", name);
                    }
                else
                    {
                    fMonitorPortList[i] = port_index;
                    }
                }
            }

        UpdateLatencies();

//    if (ioaudio_driver->midi) {
//        int err = (ioaudio_driver->midi->attach)(ioaudio_driver->midi);
//        if (err)
//            jack_error ("io-audio: cannot attach MIDI: %d", err);
//    }

        return 0;
    }

    int JackIoAudioDriver::Detach()
    {
//    ioaudio_driver_t* ioaudio_driver = (ioaudio_driver_t*)fDriver;
//    if (ioaudio_driver->midi)
//        (ioaudio_driver->midi->detach)(ioaudio_driver->midi);

        return JackAudioDriver::Detach();
    }

//static int card_to_num(const char* device)
//{
//    int err;
//    char* ctl_name;
//    snd_ctl_card_info_t *card_info;
//    snd_ctl_t* ctl_handle;
//    int i = -1;
//
//    snd_ctl_card_info_alloca (&card_info);
//
//    ctl_name = get_control_device_name(device);
//    if (ctl_name == NULL) {
//        jack_error("get_control_device_name() failed.");
//        goto fail;
//    }
//
//    if ((err = snd_ctl_open (&ctl_handle, ctl_name, 0)) < 0) {
//        jack_error ("control open \"%s\" (%s)", ctl_name,
//                    snd_strerror(err));
//        goto free;
//    }
//
//    if ((err = snd_ctl_card_info(ctl_handle, card_info)) < 0) {
//        jack_error ("control hardware info \"%s\" (%s)",
//                    device, snd_strerror (err));
//        goto close;
//    }
//
//    i = snd_ctl_card_info_get_card(card_info);
//
//close:
//    snd_ctl_close(ctl_handle);
//
//free:
//    free(ctl_name);
//
//fail:
//    return i;
//}

//int JackIoAudioDriver::Open(jack_nframes_t nframes,
//                         jack_nframes_t user_nperiods,
//                         jack_nframes_t samplerate,
//                         bool hw_monitoring,
//                         bool hw_metering,
//                         bool capturing,
//                         bool playing,
//                         DitherAlgorithm dither,
//                         bool soft_mode,
//                         bool monitor,
//                         int inchannels,
//                         int outchannels,
//                         bool shorts_first,
//                         const char* capture_driver_name,
//                         const char* playback_driver_name,
//                         jack_nframes_t capture_latency,
//                         jack_nframes_t playback_latency,
//                         const char* midi_driver_name)
    int JackIoAudioDriver::Open(
        ioaudio_driver_args_t args )
    {
        // Generic JackAudioDriver Open
        if( JackAudioDriver::Open( args.frames_per_interrupt,
                                   args.srate,
                                   args.capture,
                                   args.playback,
                                   args.user_capture_nchnls,
                                   args.user_playback_nchnls,
                                   args.monitor,
                                   args.capture_pcm_name,
                                   args.playback_pcm_name,
                                   args.systemic_input_latency,
                                   args.systemic_output_latency ) != 0 )
            {
            return -1;
            }

//    ioaudio_midi_t *midi = 0;
//#ifndef __ANDROID__
//    if (strcmp(midi_driver_name, "seq") == 0)
//        midi = ioaudio_seqmidi_new((jack_client_t*)this, 0);
//    else if (strcmp(midi_driver_name, "raw") == 0)
//        midi = ioaudio_rawmidi_new((jack_client_t*)this);
//#endif

        if( JackServerGlobals::on_device_acquire != NULL )
            {
            int capture_card = snd_card_name( args.capture_pcm_name );
            int playback_card = snd_card_name( args.playback_pcm_name );
            char audio_name[32];

            if( capture_card >= 0 )
                {
                snprintf( audio_name,
                          sizeof( audio_name ),
                          "Audio%d",
                          capture_card );
                if( !JackServerGlobals::on_device_acquire( audio_name ) )
                    {
                    jack_error( "Audio device %s cannot be acquired...",
                                args.capture_pcm_name );
                    return -1;
                    }
                }

            if( playback_card >= 0 && playback_card != capture_card )
                {
                snprintf( audio_name,
                          sizeof( audio_name ),
                          "Audio%d",
                          playback_card );
                if( !JackServerGlobals::on_device_acquire( audio_name ) )
                    {
                    jack_error( "Audio device %s cannot be acquired...",
                                args.playback_pcm_name );
                    if( capture_card >= 0 )
                        {
                        snprintf( audio_name,
                                  sizeof( audio_name ),
                                  "Audio%d",
                                  capture_card );
                        JackServerGlobals::on_device_release( audio_name );
                        }
                    return -1;
                    }
                }
            }

        fDriver = ioaudio_driver_new( (char*)"ioaudio_pcm",
                                      NULL,
                                      args );
//                                      (char*)playback_driver_name,
//                                      (char*)capture_driver_name,
//                                      NULL,
//                                      nframes,
//                                      user_nperiods,
//                                      samplerate,
//                                      hw_monitoring,
//                                      hw_metering,
//                                      capturing,
//                                      playing,
//                                      dither,
//                                      soft_mode,
//                                      monitor,
//                                      inchannels,
//                                      outchannels,
//                                      shorts_first,
//                                      capture_latency,
//                                      playback_latency /*,
//                                       midi             */
//                                      );
        if( fDriver )
            {
            // io-audio driver may have changed the in/out values
            fCaptureChannels =
                ( (ioaudio_driver_t *)fDriver )->capture_setup.format.voices;
            fPlaybackChannels =
                ( (ioaudio_driver_t *)fDriver )->playback_setup.format.voices;
            return 0;
            }
        else
            {
            JackAudioDriver::Close();
            return -1;
            }
    }

    int JackIoAudioDriver::Close()
    {
        // Generic audio driver close
        int res = JackAudioDriver::Close();

        ioaudio_driver_delete( (ioaudio_driver_t*)fDriver );

        if( JackServerGlobals::on_device_release != NULL )
            {
            char audio_name[32];
            int capture_card = snd_card_name( fCaptureDriverName );
            if( capture_card >= 0 )
                {
                snprintf( audio_name,
                          sizeof( audio_name ),
                          "Audio%d",
                          capture_card );
                JackServerGlobals::on_device_release( audio_name );
                }

            int playback_card = snd_card_name( fPlaybackDriverName );
            if( playback_card >= 0 && playback_card != capture_card )
                {
                snprintf( audio_name,
                          sizeof( audio_name ),
                          "Audio%d",
                          playback_card );
                JackServerGlobals::on_device_release( audio_name );
                }
            }

        return res;
    }

    int JackIoAudioDriver::Start()
    {
        int res = JackAudioDriver::Start();
        if( res >= 0 )
            {
            res = ioaudio_driver_start( (ioaudio_driver_t *)fDriver );
            if( res < 0 )
                {
                JackAudioDriver::Stop();
                }
            }
        return res;
    }

    int JackIoAudioDriver::Stop()
    {
        int res = ioaudio_driver_stop( (ioaudio_driver_t *)fDriver );
        if( JackAudioDriver::Stop() < 0 )
            {
            res = -1;
            }
        return res;
    }

    int JackIoAudioDriver::Read()
    {
        /* Taken from ioaudio_driver_run_cycle */
        int wait_status;
        jack_nframes_t nframes;
        fDelayedUsecs = 0.f;

        retry:

        nframes = ioaudio_driver_wait( (ioaudio_driver_t *)fDriver,
                                       -1,
                                       &wait_status,
                                       &fDelayedUsecs );

        if( wait_status < 0 )
            return -1; /* driver failed */

        if( nframes == 0 )
            {
            /* we detected an xrun and restarted: notify
             * clients about the delay.
             */
            jack_log( "io-audio XRun wait_status = %d",
                      wait_status );
            NotifyXRun( fBeginDateUst,
                        fDelayedUsecs );
            goto retry;
            /* recoverable error*/
            }

        if( nframes != fEngineControl->fBufferSize )
            jack_log(
                      "JackIoAudioDriver::Read warning fBufferSize = %ld nframes = %ld",
                      fEngineControl->fBufferSize,
                      nframes );

        // Has to be done before read
        JackDriver::CycleIncTime();

        return ioaudio_driver_read( (ioaudio_driver_t *)fDriver,
                                    fEngineControl->fBufferSize );
    }

    int JackIoAudioDriver::Write()
    {
        return ioaudio_driver_write( (ioaudio_driver_t *)fDriver,
                                     fEngineControl->fBufferSize );
    }

    void JackIoAudioDriver::ReadInputAux(
        jack_nframes_t orig_nframes,
        ssize_t contiguous,
        ssize_t nread )
    {
        for( int chn = 0; chn < fCaptureChannels; chn++ )
            {
            if( fGraphManager->GetConnectionsNum( fCapturePortList[chn] ) > 0 )
                {
                jack_default_audio_sample_t* buf =
                    (jack_default_audio_sample_t*)fGraphManager->GetBuffer(
                                                                            fCapturePortList[chn],
                                                                            orig_nframes );
                ioaudio_driver_read_from_channel( (ioaudio_driver_t *)fDriver,
                                                  chn,
                                                  buf + nread,
                                                  contiguous );
                }
            }
    }

    void JackIoAudioDriver::MonitorInputAux()
    {
        for( int chn = 0; chn < fCaptureChannels; chn++ )
            {
            JackPort* port = fGraphManager->GetPort( fCapturePortList[chn] );
            if( port->MonitoringInput() )
                {
                ( (ioaudio_driver_t *)fDriver )->input_monitor_mask |=
                    ( 1 << chn );
                }
            }
    }

    void JackIoAudioDriver::ClearOutputAux()
    {
        for( int chn = 0; chn < fPlaybackChannels; chn++ )
            {
            jack_default_audio_sample_t* buf =
                (jack_default_audio_sample_t*)fGraphManager->GetBuffer(
                                                                        fPlaybackPortList[chn],
                                                                        fEngineControl->fBufferSize );
            memset( buf,
                    0,
                    sizeof(jack_default_audio_sample_t)
                        * fEngineControl->fBufferSize );
            }
    }

    void JackIoAudioDriver::SetTimetAux(
        jack_time_t time )
    {
        fBeginDateUst = time;
    }

    void JackIoAudioDriver::WriteOutputAux(
        jack_nframes_t orig_nframes,
        ssize_t contiguous,
        ssize_t nwritten )
    {
        for( int chn = 0; chn < fPlaybackChannels; chn++ )
            {
            // Output ports
            if( fGraphManager->GetConnectionsNum( fPlaybackPortList[chn] ) > 0 )
                {
                jack_default_audio_sample_t* buf =
                    (jack_default_audio_sample_t*)fGraphManager->GetBuffer(
                                                                            fPlaybackPortList[chn],
                                                                            orig_nframes );
                ioaudio_driver_write_to_channel( ( (ioaudio_driver_t *)fDriver ),
                                                 chn,
                                                 buf + nwritten,
                                                 contiguous );
                // Monitor ports
                if( fWithMonitorPorts
                    && fGraphManager->GetConnectionsNum(
                                                         fMonitorPortList[chn] )
                        > 0 )
                    {
                    jack_default_audio_sample_t* monbuf =
                        (jack_default_audio_sample_t*)fGraphManager->GetBuffer(
                                                                                fMonitorPortList[chn],
                                                                                orig_nframes );
                    memcpy( monbuf + nwritten,
                            buf + nwritten,
                            contiguous * sizeof(jack_default_audio_sample_t) );
                    }
                }
            }
    }

    int JackIoAudioDriver::is_realtime() const
    {
        return fEngineControl->fRealTime;
    }

    int JackIoAudioDriver::create_thread(
        pthread_t *thread,
        int priority,
        int realtime,
        void *(*start_routine)(
            void* ),
        void *arg )
    {
#ifdef __ANDROID__
        return JackAndroidThread::StartImp(thread, priority, realtime, start_routine, arg);
#else
        return JackPosixThread::StartImp( thread,
                                          priority,
                                          realtime,
                                          start_routine,
                                          arg );
#endif
    }

    jack_port_id_t JackIoAudioDriver::port_register(
        const char *port_name,
        const char *port_type,
        unsigned long flags,
        unsigned long buffer_size )
    {
        jack_port_id_t port_index;
        int res = fEngine->PortRegister( fClientControl.fRefNum,
                                         port_name,
                                         port_type,
                                         flags,
                                         buffer_size,
                                         &port_index );
        return ( res == 0 ) ? port_index : 0;
    }

    int JackIoAudioDriver::port_unregister(
        jack_port_id_t port_index )
    {
        return fEngine->PortUnRegister( fClientControl.fRefNum,
                                        port_index );
    }

    void* JackIoAudioDriver::port_get_buffer(
        int port,
        jack_nframes_t nframes )
    {
        return fGraphManager->GetBuffer( port,
                                         nframes );
    }

    int JackIoAudioDriver::port_set_alias(
        int port,
        const char* name )
    {
        return fGraphManager->GetPort( port )->SetAlias( name );
    }

    jack_nframes_t JackIoAudioDriver::get_sample_rate() const
    {
        return fEngineControl->fSampleRate;
    }

    jack_nframes_t JackIoAudioDriver::frame_time() const
    {
        JackTimer timer;
        fEngineControl->ReadFrameTime( &timer );
        return timer.Time2Frames( GetMicroSeconds(),
                                  fEngineControl->fBufferSize );
    }

    jack_nframes_t JackIoAudioDriver::last_frame_time() const
    {
        JackTimer timer;
        fEngineControl->ReadFrameTime( &timer );
        return timer.CurFrame();
    }

} // end of namespace

#ifdef __cplusplus
extern "C"
{
#endif

    static jack_driver_param_constraint_desc_t *
    enum_ioaudio_devices()
    {
        snd_ctl_t * handle;
        snd_ctl_hw_info_t hwinfo;
        snd_pcm_info_t pcminfo;
        int card_no = -1;
        jack_driver_param_value_t card_id;
        jack_driver_param_value_t device_id;
        char description[64];
        uint32_t device_no;
        bool has_capture;
        bool has_playback;
        jack_driver_param_constraint_desc_t * constraint_ptr;
        uint32_t array_size = 0;

        constraint_ptr = NULL;

        int cards_over = 0;
        int numcards = snd_cards_list( NULL,
                                       0,
                                       &cards_over );
        int* cards = static_cast<int*>( malloc( cards_over * sizeof(int) ) );
        numcards = snd_cards_list( cards,
                                   cards_over,
                                   &cards_over );

        for( int c = 0; c < numcards; ++c )
            {
            card_no = cards[c];

            if( snd_ctl_open( &handle,
                              card_no ) >= 0
                && snd_ctl_hw_info( handle,
                                    &hwinfo ) >= 0 )
                {
                strncpy( card_id.str,
                         hwinfo.id,
                         sizeof( card_id.str ) );
                strncpy( description,
                         hwinfo.longname,
                         sizeof( description ) );
                if( !jack_constraint_add_enum( &constraint_ptr,
                                               &array_size,
                                               &card_id,
                                               description ) )
                    goto fail;

                device_no = -1;

                for( device_no = 0; device_no < hwinfo.pcmdevs; ++device_no )
                    {
                    snprintf( device_id.str,
                              sizeof( device_id.str ),
                              "%s,%d",
                              card_id.str,
                              device_no );

                    snd_ctl_pcm_info( handle,
                                      device_no,
                                      &pcminfo );
                    has_capture = pcminfo.flags & SND_PCM_INFO_CAPTURE;
                    has_playback = pcminfo.flags & SND_PCM_INFO_PLAYBACK;

                    if( has_capture && has_playback )
                        {
                        snprintf( description,
                                  sizeof( description ),
                                  "%s (duplex)",
                                  pcminfo.name );
                        }
                    else if( has_capture )
                        {
                        snprintf( description,
                                  sizeof( description ),
                                  "%s (capture)",
                                  pcminfo.name );
                        }
                    else if( has_playback )
                        {
                        snprintf( description,
                                  sizeof( description ),
                                  "%s (playback)",
                                  pcminfo.name );
                        }
                    else
                        {
                        continue;
                        }

                    if( !jack_constraint_add_enum( &constraint_ptr,
                                                   &array_size,
                                                   &device_id,
                                                   description ) )
                        goto fail;
                    }

                snd_ctl_close( handle );
                }
            }

        return constraint_ptr;
        fail: jack_constraint_free( constraint_ptr );
        return NULL;
    }

    static int dither_opt(
        char c,
        DitherAlgorithm* dither )
    {
        switch( c )
            {
            case '-':
                case 'n':
                *dither = None;
                break;

            case 'r':
                *dither = Rectangular;
                break;

            case 's':
                *dither = Shaped;
                break;

            case 't':
                *dither = Triangular;
                break;

            default:
                fprintf( stderr,
                         "io-audio driver: illegal dithering mode %c\n",
                         c );
                return -1;
            }
        return 0;
    }

    SERVER_EXPORT const jack_driver_desc_t* driver_get_descriptor()
    {
        jack_driver_desc_t * desc;
        jack_driver_desc_filler_t filler;
        jack_driver_param_value_t value;

        desc =
            jack_driver_descriptor_construct( "io-audio",
                                              JackDriverMaster,
                                              "QNX io-audio API based audio backend",
                                              &filler );

        strcpy( value.str,
                "pcmPreferredp" );
#ifdef __ANDROID__
        jack_driver_descriptor_add_parameter(desc, &filler, "device", 'd', JackDriverParamString, &value, NULL, "io-audio device name", NULL);
#else
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "device",
                                              'd',
                                              JackDriverParamString,
                                              &value,
                                              enum_ioaudio_devices(),
                                              "io-audio device name",
                                              NULL );
#endif

        strcpy( value.str,
                "none" );
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "capture",
                                              'C',
                                              JackDriverParamString,
                                              &value,
                                              NULL,
                                              "Provide capture ports.  Optionally set device",
                                              NULL );
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "playback",
                                              'P',
                                              JackDriverParamString,
                                              &value,
                                              NULL,
                                              "Provide playback ports.  Optionally set device",
                                              NULL );

        value.ui = 48000U;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "rate",
                                              'r',
                                              JackDriverParamUInt,
                                              &value,
                                              NULL,
                                              "Sample rate",
                                              NULL );

        value.ui = 1024U;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "period",
                                              'p',
                                              JackDriverParamUInt,
                                              &value,
                                              NULL,
                                              "Frames per period",
                                              NULL );

        value.ui = 2U;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "nperiods",
                                              'n',
                                              JackDriverParamUInt,
                                              &value,
                                              NULL,
                                              "Number of periods of playback latency",
                                              NULL );

        value.i = 0;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "hwmon",
                                              'H',
                                              JackDriverParamBool,
                                              &value,
                                              NULL,
                                              "Hardware monitoring, if available",
                                              NULL );

        value.i = 0;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "hwmeter",
                                              'M',
                                              JackDriverParamBool,
                                              &value,
                                              NULL,
                                              "Hardware metering, if available",
                                              NULL );

        value.i = 1;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "duplex",
                                              'D',
                                              JackDriverParamBool,
                                              &value,
                                              NULL,
                                              "Provide both capture and playback ports",
                                              NULL );

        value.i = 0;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "softmode",
                                              's',
                                              JackDriverParamBool,
                                              &value,
                                              NULL,
                                              "Soft-mode, no xrun handling",
                                              NULL );

        value.i = 0;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "monitor",
                                              'm',
                                              JackDriverParamBool,
                                              &value,
                                              NULL,
                                              "Provide monitor ports for the output",
                                              NULL );

        value.c = 'n';
        jack_driver_descriptor_add_parameter(
                                              desc,
                                              &filler,
                                              "dither",
                                              'z',
                                              JackDriverParamChar,
                                              &value,
                                              jack_constraint_compose_enum_char(
                                                                                 JACK_CONSTRAINT_FLAG_STRICT
                                                                                     | JACK_CONSTRAINT_FLAG_FAKE_VALUE,
                                                                                 dither_constraint_descr_array ),
                                              "Dithering mode",
                                              NULL );

        value.ui = 0;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "inchannels",
                                              'i',
                                              JackDriverParamUInt,
                                              &value,
                                              NULL,
                                              "Number of capture channels (defaults to hardware max)",
                                              NULL );
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "outchannels",
                                              'o',
                                              JackDriverParamUInt,
                                              &value,
                                              NULL,
                                              "Number of playback channels (defaults to hardware max)",
                                              NULL );

        value.i = FALSE;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "shorts",
                                              'S',
                                              JackDriverParamBool,
                                              &value,
                                              NULL,
                                              "Try 16-bit samples before 32-bit",
                                              NULL );

        value.ui = 0;
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "input-latency",
                                              'I',
                                              JackDriverParamUInt,
                                              &value,
                                              NULL,
                                              "Extra input latency (frames)",
                                              NULL );
        jack_driver_descriptor_add_parameter( desc,
                                              &filler,
                                              "output-latency",
                                              'O',
                                              JackDriverParamUInt,
                                              &value,
                                              NULL,
                                              "Extra output latency (frames)",
                                              NULL );

        strcpy( value.str,
                "none" );
        jack_driver_descriptor_add_parameter(
                                              desc,
                                              &filler,
                                              "midi-driver",
                                              'X',
                                              JackDriverParamString,
                                              &value,
                                              jack_constraint_compose_enum_str(
                                                                                JACK_CONSTRAINT_FLAG_STRICT
                                                                                    | JACK_CONSTRAINT_FLAG_FAKE_VALUE,
                                                                                midi_constraint_descr_array ),
                                              "io-audio MIDI driver",
                                              NULL );

        return desc;
    }

    static Jack::JackIoAudioDriver* g_ioaudio_driver;

    SERVER_EXPORT Jack::JackDriverClientInterface* driver_initialize(
        Jack::JackLockedEngine* engine,
        Jack::JackSynchro* table,
        const JSList* params )
    {
        ioaudio_driver_args_t args;
        args.srate = 48000;
        args.frames_per_interrupt = 1024;
        args.user_nperiods = 2;
        args.playback_pcm_name = "pcmPreferredp";
        args.capture_pcm_name = "pcmPreferredc";
        args.hw_monitoring = FALSE;
        args.hw_metering = FALSE;
        args.capture = FALSE;
        args.playback = FALSE;
        args.soft_mode = FALSE;
        args.monitor = FALSE;
        args.dither = None;
        args.user_capture_nchnls = 0;
        args.user_playback_nchnls = 0;
        args.shorts_first = FALSE;
        args.systemic_input_latency = 0;
        args.systemic_output_latency = 0;
        args.midi_driver = "none";

        const JSList * node;
        const jack_driver_param_t * param;

        for( node = params; node; node = jack_slist_next( node ) )
            {
            param = (const jack_driver_param_t *)node->data;

            switch( param->character )
                {

                case 'C':
                    args.capture = TRUE;
                    if( strcmp( param->value.str,
                                "none" ) != 0 )
                        {
                        args.capture_pcm_name = strdup( param->value.str );
                        jack_log( "capture device %s",
                                  args.capture_pcm_name );
                        }
                    break;

                case 'P':
                    args.playback = TRUE;
                    if( strcmp( param->value.str,
                                "none" ) != 0 )
                        {
                        args.playback_pcm_name = strdup( param->value.str );
                        jack_log( "playback device %s",
                                  args.playback_pcm_name );
                        }
                    break;

                case 'D':
                    args.playback = TRUE;
                    args.capture = TRUE;
                    break;

                case 'd':
                    if( strcmp( param->value.str,
                                "none" ) != 0 )
                        {
                        args.playback_pcm_name = strdup( param->value.str );
                        args.capture_pcm_name = strdup( param->value.str );
                        jack_log( "playback device %s",
                                  args.playback_pcm_name );
                        jack_log( "capture device %s",
                                  args.capture_pcm_name );
                        }
                    break;

                case 'H':
                    args.hw_monitoring = param->value.i;
                    break;

                case 'm':
                    args.monitor = param->value.i;
                    break;

                case 'M':
                    args.hw_metering = param->value.i;
                    break;

                case 'r':
                    args.srate = param->value.ui;
                    jack_log( "apparent rate = %d",
                              args.srate );
                    break;

                case 'p':
                    args.frames_per_interrupt = param->value.ui;
                    jack_log( "frames per period = %d",
                              args.frames_per_interrupt );
                    break;

                case 'n':
                    args.user_nperiods = param->value.ui;
                    if( args.user_nperiods < 2 )
                        { /* enforce minimum value */
                        args.user_nperiods = 2;
                        }
                    break;

                case 's':
                    args.soft_mode = param->value.i;
                    break;

                case 'z':
                    if( dither_opt( param->value.c,
                                    &args.dither ) )
                        {
                        return NULL;
                        }
                    break;

                case 'i':
                    args.user_capture_nchnls = param->value.ui;
                    break;

                case 'o':
                    args.user_playback_nchnls = param->value.ui;
                    break;

                case 'S':
                    args.shorts_first = param->value.i;
                    break;

                case 'I':
                    args.systemic_input_latency = param->value.ui;
                    break;

                case 'O':
                    args.systemic_output_latency = param->value.ui;
                    break;

                case 'X':
                    args.midi_driver = strdup( param->value.str );
                    break;
                }
            }

        /* duplex is the default */
        if( !args.capture && !args.playback )
            {
            args.capture = TRUE;
            args.playback = TRUE;
            }

        g_ioaudio_driver = new Jack::JackIoAudioDriver( "system",
                                                        "ioaudio_pcm",
                                                        engine,
                                                        table );
        Jack::JackDriverClientInterface* threaded_driver =
            new Jack::JackThreadedDriver( g_ioaudio_driver );
        // Special open for io-audio driver...
        if( g_ioaudio_driver->Open( args ) == 0 )
            {
            return threaded_driver;
            }
        else
            {
            delete threaded_driver; // Delete the decorated driver
            return NULL;
            }
    }

// Code to be used in ioaudio_driver.c

    void ReadInput(
        jack_nframes_t orig_nframes,
        ssize_t contiguous,
        ssize_t nread )
    {
        g_ioaudio_driver->ReadInputAux( orig_nframes,
                                        contiguous,
                                        nread );
    }
    void MonitorInput()
    {
        g_ioaudio_driver->MonitorInputAux();
    }
    void ClearOutput()
    {
        g_ioaudio_driver->ClearOutputAux();
    }
    void WriteOutput(
        jack_nframes_t orig_nframes,
        ssize_t contiguous,
        ssize_t nwritten )
    {
        g_ioaudio_driver->WriteOutputAux( orig_nframes,
                                          contiguous,
                                          nwritten );
    }
    void SetTime(
        jack_time_t time )
    {
        g_ioaudio_driver->SetTimetAux( time );
    }

    int Restart()
    {
        int res;
        if( ( res = g_ioaudio_driver->Stop() ) == 0 )
            {
            res = g_ioaudio_driver->Start();
            }
        return res;
    }

#ifdef __cplusplus
}
#endif

